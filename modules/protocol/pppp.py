# modules/protocol/pppp.py
from dataclasses import dataclass
import struct
import logging
from typing import Union
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
    reserved: int = 0

    def to_bytes(self) -> bytes:
        # >BBHB: Big-Endian, U8, U8, U16, U8
        return struct.pack('>BBHB', self.session_type, self.subcommand, self.sequence, self.reserved)

class PPPPProtocol:
    def __init__(self, start_sequence: int = 1):
        self.pppp_sequence = start_sequence

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
        FIX #44: First init packet (0xF1E0) with 4-byte payload 0x00000000.
        
        From tcpdump_1800_connect.log (17:55:23.927):
        IP 192.168.43.22.54530 > 192.168.43.1.40611: UDP, length 4
        0x0000:  4500 0020 8146 4000 4011 e21e c0a8 2b16
        0x0010:  c0a8 2b01 d502 9ea3 000c c2e6 f1e0 0000
        
        Packet structure: F1 E0 [4-byte payload: 00 00 00 00]
        Total UDP payload: 8 bytes (4 outer header + 4 payload)
        
        This is sent BEFORE 0xF1E1 packet.
        """
        outer = PPPPOuterHeader(
            magic=PPPPConstants.MAGIC_STANDARD,  # 0xF1
            cmd_type=0xE0,  # First init type
            length=4  # 4-byte payload
        )
        payload = b'\x00\x00\x00\x00'  # Magic init value
        packet = outer.to_bytes() + payload
        logger.debug(f"[PPPP] wrap_init_ping (0xE0): {packet.hex()}")
        return packet

    def wrap_init_secondary(self) -> bytes:
        """
        FIX #44: Second init packet (0xF1E1) with 4-byte payload 0x00000000.
        
        From tcpdump_1800_connect.log (17:55:23.928):
        IP 192.168.43.22.54530 > 192.168.43.1.40611: UDP, length 4
        0x0000:  4500 0020 8147 4000 4011 e21d c0a8 2b16
        0x0010:  c0a8 2b01 d502 9ea3 000c c2e5 f1e1 0000
        
        Packet structure: F1 E1 [4-byte payload: 00 00 00 00]
        Total UDP payload: 8 bytes (4 outer header + 4 payload)
        
        This is sent AFTER 0xF1E0 packet.
        """
        outer = PPPPOuterHeader(
            magic=PPPPConstants.MAGIC_STANDARD,  # 0xF1
            cmd_type=0xE1,  # Second init type
            length=4  # 4-byte payload
        )
        payload = b'\x00\x00\x00\x00'  # Magic init value
        packet = outer.to_bytes() + payload
        logger.debug(f"[PPPP] wrap_init_secondary (0xE1): {packet.hex()}")
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
        Format: F1 D1 [Len] [D1 00 Seq 00] [ArtemisSeq]
        """
        # Payload is Artemis Sequence (2 bytes)
        payload = struct.pack('>H', artemis_seq)

        # Inner Header
        # Type=D1, Sub=00, Seq=next, Res=00
        seq = self._increment_sequence()
        inner = PPPPInnerHeader(
            session_type=0xD1,
            subcommand=0x00,
            sequence=seq,
            reserved=0x00
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

    def wrap_login(self, artemis_payload: bytes) -> bytes:
        """
        FIX #44: Wraps Artemis login payload with 0xF1D0 outer type.
        
        From tcpdump_1800_connect.log (17:55:25.600):
        IP 192.168.43.22.54530 > 192.168.43.1.40611: UDP, length 53
        0xf1d0 0031 d100 0003 ARTEMIS\x00...
        
        Outer Type: 0xD0 (LOGIN, not 0xD1 DISCOVERY!)
        Inner Header: D1 00 [Seq] 00
        Artemis Payload: ARTEMIS\x00 + version + sequence + token_len + token
        
        This is the CRITICAL difference from discovery.
        """
        # Validate payload size
        if len(artemis_payload) > 4088:  # 4096 - headers
            raise ValueError(f"Payload too large: {len(artemis_payload)}")

        # Inner Header with sequence
        seq = self._increment_sequence()
        inner = PPPPInnerHeader(
            session_type=0xD1,  # Inner type is D1
            subcommand=0x00,
            sequence=seq,
            reserved=0x00
        )
        inner_bytes = inner.to_bytes()

        # Outer Header with LOGIN type (0xD0)
        total_len = len(inner_bytes) + len(artemis_payload)
        outer = PPPPOuterHeader(
            magic=PPPPConstants.MAGIC_STANDARD,  # 0xF1
            cmd_type=PPPPConstants.CMD_LOGIN,  # 0xD0 (CRITICAL!)
            length=total_len
        )

        packet = outer.to_bytes() + inner_bytes + artemis_payload
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
            sequence=seq,
            reserved=0x00
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
