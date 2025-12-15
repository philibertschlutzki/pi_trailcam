# modules/protocol/pppp.py
from dataclasses import dataclass
import struct
import logging
from typing import Union, Dict
from modules.protocol.constants import PPPPConstants

logger = logging.getLogger(__name__)

@dataclass
class PPPPOuterHeader:
    magic: int
    cmd_type: int
    length: int

    def to_bytes(self) -> bytes:
        # >BBH: Big-Endian, U8, U8, U16
        return struct.pack('>BBH', self.magic, self.cmd_type, self.length)

@dataclass
class PPPPInnerHeader:
    session_type: int
    subcommand: int
    sequence: int
    # Reserved field removed to match observed correct packet structure
    # reserved: int = 0

    def to_bytes(self) -> bytes:
        # >BBH: Big-Endian, U8, U8, U16
        # Was >BBHB (5 bytes), now 4 bytes to match camera expectations
        return struct.pack('>BBH', self.session_type, self.subcommand, self.sequence)

class PPPPProtocol:
    def __init__(self, start_sequence: int = 1, logger=None):
        self.pppp_sequence = start_sequence
        self.logger = logger or logging.getLogger(__name__)

    def _increment_sequence(self) -> int:
        """Increment sequence and wrap around at 0xFFFF (65535) -> 1"""
        # Note: Memory says "must roll over to 1 upon exceeding 65535"
        # 1-based sequence
        current = self.pppp_sequence
        self.pppp_sequence += 1
        if self.pppp_sequence > 0xFFFF:
            self.pppp_sequence = 1
        return current

    def wrap_init_ping(self) -> bytes:
        """
        First init packet (0xF1E0).
        Matches capture 'export packets.txt' where Frame 2731 is 'f1 e0 00 00'.
        Length 0, no payload.
        """
        outer = PPPPOuterHeader(
            magic=PPPPConstants.MAGIC_STANDARD,  # 0xF1
            cmd_type=0xE0,  # First init type
            length=0  # Changed from 4 to 0 based on correct packet capture
        )
        packet = outer.to_bytes() # No payload
        logger.debug(f"[PPPP] wrap_init_ping (0xE0): {packet.hex()}")
        return packet

    def wrap_init_secondary(self) -> bytes:
        """
        Second init packet (0xF1E1).
        Assuming symmetry with 0xF1E0, using length 0.
        """
        outer = PPPPOuterHeader(
            magic=PPPPConstants.MAGIC_STANDARD,  # 0xF1
            cmd_type=0xE1,  # Second init type
            length=0  # Changed from 4 to 0
        )
        packet = outer.to_bytes() # No payload
        logger.debug(f"[PPPP] wrap_init_secondary (0xE1): {packet.hex()}")
        return packet

    def wrap_lan_search(self) -> bytes:
        """
        Creates the LAN Search Broadcast packet (0xF130).
        Format: F1 30 00 00 (No payload)

        This packet is broadcast to port 32108 to discover the camera.
        """
        outer = PPPPOuterHeader(
            magic=PPPPConstants.MAGIC_STANDARD,
            cmd_type=PPPPConstants.CMD_LAN_SEARCH, # 0x30
            length=0
        )
        packet = outer.to_bytes()
        logger.debug(f"[PPPP] wrap_lan_search (0x30): {packet.hex()}")
        return packet

    def wrap_init(self) -> bytes:
        """
        Legacy wrapper for backward compatibility.
        Now returns 0xE1 packet (secondary init).
        For full init sequence, use wrap_init_ping() + wrap_init_secondary().
        """
        return self.wrap_init_secondary()

    def wrap_discovery(self, artemis_seq: int) -> bytes:
        """
        Wraps a discovery payload (2 bytes Artemis Sequence).
        Format: F1 D1 [Len] [D1 00 Seq] [ArtemisSeq]
        """
        # Payload is Artemis Sequence (2 bytes)
        payload = struct.pack('>H', artemis_seq)

        # Inner Header
        # Type=D1, Sub=00, Seq=next
        seq = self._increment_sequence()
        inner = PPPPInnerHeader(
            session_type=0xD1,
            subcommand=0x00,
            sequence=seq
        )
        inner_bytes = inner.to_bytes()

        # Outer Header
        # Type=D1
        total_len = len(inner_bytes) + len(payload)
        outer = PPPPOuterHeader(
            magic=PPPPConstants.MAGIC_STANDARD,
            cmd_type=PPPPConstants.CMD_DISCOVERY,
            length=total_len
        )
        outer_bytes = outer.to_bytes()

        packet = outer_bytes + inner_bytes + payload
        logger.debug(f"[PPPP] wrap_discovery: seq={seq}, length={total_len}, payload={payload.hex()}")
        return packet

    def validate_packet(self, packet: bytes) -> bool:
        """
        Validate a PPPP packet before sending.

        Checks:
        - Magic 0xF1
        - PPPP Header Length
        - Artemis Signature (if present)
        - Packet Length Consistency
        """
        if len(packet) < 4:
            raise ValueError("Packet too short")

        # Check Magic
        if packet[0] != 0xF1:
             raise ValueError(f"Invalid PPPP Header: {packet[:2].hex()}")

        # Parse Length Field
        pkt_len = (packet[2] << 8) | packet[3]
        if len(packet) != pkt_len + 4:
            raise ValueError(f"Length mismatch: header={pkt_len}, actual={len(packet)-4}")

        # Check Artemis Signature (only for Login packets typically, but general check)
        # Login (0xD0) usually has Artemis signature starting at offset 8 (Header 4 + Inner 4)
        if packet[1] == 0xD0: # Login Type
             if len(packet) >= 16:
                 # Check Signature at offset 8 (Header=4 + Inner=4 = 8)
                 sig = packet[8:16]
                 # Must be ARTEMIS\x00
                 if sig != b'ARTEMIS\x00':
                      raise ValueError(f"Invalid Artemis Signature: {sig.hex()}")

        return True

    def wrap_login(self, artemis_payload: bytes) -> bytes:
        """
        Wraps Artemis login payload with 0xF1D0 outer type.
        
        Outer Type: 0xD0 (LOGIN)
        Inner Header: D1 00 [Seq] (4 bytes)
        Artemis Payload: ARTEMIS\x00...
        """
        # Validate payload size
        if len(artemis_payload) > 4088:  # 4096 - headers
            raise ValueError(f"Payload too large: {len(artemis_payload)}")

        # Inner Header with sequence
        seq = self._increment_sequence()
        inner = PPPPInnerHeader(
            session_type=0xD1,  # Inner type is D1
            subcommand=0x03,  # Subcommand 0x03 = Login
            sequence=seq
        )
        inner_bytes = inner.to_bytes()

        # Outer Header with LOGIN type (0xD0)
        total_len = len(inner_bytes) + len(artemis_payload)
        outer = PPPPOuterHeader(
            magic=PPPPConstants.MAGIC_STANDARD,  # 0xF1
            cmd_type=PPPPConstants.CMD_LOGIN,  # 0xD0
            length=total_len
        )

        packet = outer.to_bytes() + inner_bytes + artemis_payload

        # Validation
        self.validate_packet(packet)

        logger.debug(f"[PPPP] wrap_login: outer=0xD0, seq={seq}, length={total_len}")
        return packet

    def wrap_heartbeat(self, json_payload: bytes) -> bytes:
        """
        Wraps a heartbeat/command payload.
        Format: F1 D3 [Len] [InnerHeader] [JSON]
        """
        if len(json_payload) > 4088:
            raise ValueError("Payload too large")

        seq = self._increment_sequence()
        inner = PPPPInnerHeader(
            session_type=0xD1,
            subcommand=0x00,
            sequence=seq
        )
        inner_bytes = inner.to_bytes()

        total_len = len(inner_bytes) + len(json_payload)
        outer = PPPPOuterHeader(
            magic=PPPPConstants.MAGIC_STANDARD,
            cmd_type=PPPPConstants.CMD_CONTROL,  # D3
            length=total_len
        )

        packet = outer.to_bytes() + inner_bytes + json_payload
        logger.debug(f"[PPPP] wrap_heartbeat: seq={seq}, length={total_len}")
        return packet

    def wrap_command(self, json_bytes: bytes) -> bytes:
        """
        Alias for wrap_heartbeat / control commands.
        Usually uses same structure (D3 or D1).
        """
        return self.wrap_heartbeat(json_bytes)

    def unwrap_pppp(self, packet: bytes) -> Dict:
        """
        Unwrap PPPP packet to extract Artemis payload.
        Ported from PPPPWrapper.

        Args:
            packet: Complete PPPP packet received from camera

        Returns:
            Dictionary containing:
                - outer_magic: Should be 0xF1
                - outer_type: PPPP command type
                - length: Payload length from header
                - inner_type: PPPP session type
                - subcommand: Subcommand byte (0x01=ACK, 0x04=Login ACK, etc.)
                - pppp_seq: PPPP sequence number from packet
                - payload: Raw Artemis data (bytes)
        """
        if len(packet) < 8:
            raise ValueError(f"PPPP packet too short: {len(packet)} bytes (minimum 8)")

        # Parse Outer Header (4 bytes)
        # >BBH: Big-Endian, U8, U8, U16
        outer_magic, outer_type, length = struct.unpack('>BBH', packet[0:4])

        if outer_magic != PPPPConstants.MAGIC_STANDARD: # 0xF1
             self.logger.warning(
                 f"[PPPP UNWRAP] Unexpected magic: 0x{outer_magic:02X} "
                 f"(expected 0x{PPPPConstants.MAGIC_STANDARD:02X})"
             )

        # Parse Inner Header
        # Matches >BBH (4 bytes) used in sending now.
        inner_type, subcommand, pppp_seq = struct.unpack('>BBH', packet[4:8])

        # Payload
        artemis_payload = packet[8:]

        self.logger.debug(
            f"[PPPP UNWRAP] "
            f"Outer=0x{outer_type:02X}, "
            f"Inner=0x{inner_type:02X}, "
            f"Sub=0x{subcommand:02X}, "
            f"Seq={pppp_seq}, "
            f"PayloadLen={len(artemis_payload)}"
        )

        return {
            'outer_magic': outer_magic,
            'outer_type': outer_type,
            'length': length,
            'inner_type': inner_type,
            'subcommand': subcommand,
            'pppp_seq': pppp_seq,
            'payload': artemis_payload,
        }

    def reset_sequence(self, start_value: int = 1):
        """Reset PPPP sequence counter"""
        self.pppp_sequence = start_value
        logger.debug(f"[PPPP] Sequence reset to {start_value}")

    def get_sequence(self) -> int:
        """Get current PPPP sequence value"""
        return self.pppp_sequence

if __name__ == "__main__":
    # Test execution
    logging.basicConfig(level=logging.DEBUG)
    protocol = PPPPProtocol()
    
    # Test init sequence
    print("\nInit Sequence:")
    ping = protocol.wrap_init_ping()
    print(f"1. Init Ping (0xE0): {ping.hex()}")
    secondary = protocol.wrap_init_secondary()
    print(f"2. Init Secondary (0xE1): {secondary.hex()}")
    
    # Test discovery
    print("\nDiscovery:")
    discovery = protocol.wrap_discovery(0x0003)
    print(f"Discovery (0xD1): {discovery.hex()}")
    
    # Test login
    print("\nLogin:")
    artemis_payload = b'ARTEMIS\x00' + b'\x02\x00\x00\x00' + b'\x02\x00\x01\x00' + b'\x19\x00\x00\x00' + b'test_token\x00'
    login = protocol.wrap_login(artemis_payload)
    print(f"Login (0xD0): {login.hex()}")
    print(f"Expected outer type: 0xD0, got: 0x{login[1]:02X}")

    # Test Unwrap
    print("\nUnwrap:")
    # Simulate a response packet with 4-byte inner header
    # Outer(F1, D1, len=4) + Inner(D1, 01, Seq=1) + Payload(empty)
    # Inner = D1 01 00 01 (4 bytes)
    response_packet = b'\xf1\xd1\x00\x04\xd1\x01\x00\x01'
    unwrapped = protocol.unwrap_pppp(response_packet)
    print(f"Unwrapped: {unwrapped}")
