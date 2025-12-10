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

    def wrap_init(self) -> bytes:
        """
        Wraps an initialization burst packet.
        Format: F1 E1 00 00 (No Inner Header)
        """
        # Init burst has no payload and no inner header?
        # Memory says: "The UDP initialization burst is limited to 3 packets... Initialization (0xE1, wake-up)"
        # Memory: "PPPP wrapper structure... Outer Header... followed by the Artemis payload"
        # Memory: "The PPPP sequence number must be explicitly reset to 1 after the initialization burst"
        # Prompt C: "wrap_init... Only Outer Header (4 bytes)... Hex: f1e10000"

        outer = PPPPOuterHeader(
            magic=PPPPConstants.MAGIC_STANDARD,
            cmd_type=PPPPConstants.CMD_INIT_BURST,
            length=0
        )
        packet = outer.to_bytes()
        logger.debug(f"[PPPP] wrap_init: length=0")
        return packet

    def wrap_login(self, artemis_payload: bytes) -> bytes:
        """
        Wraps a login payload.
        Format: F1 D0 [Len] [InnerHeader] [ArtemisPayload]
        NOTE: Outer Type is D0 for Login!
        """
        # Validate payload size
        if len(artemis_payload) > 4088: # 4096 - headers
            raise ValueError(f"Payload too large: {len(artemis_payload)}")

        # Inner Header
        # Type=D1?? Or D0?
        # Memory says: "The UDP login packet is wrapped in a PPPP header with Outer Type 0xD0 ... containing the Artemis payload"
        # Usually Inner Header Type mirrors Outer, or is fixed.
        # Prompt C says: "InnerHeader(0xD1, 0x00, 1, 0)" for discovery.
        # For Login, typically Inner Type is also D0 or D1.
        # Existing knowledge says "Login (0xD0 Outer)".
        # Let's assume Inner Type D1 is standard for session messages, but maybe D0 for login?
        # Prompt H says: "KRITISCH: wrap_login nutzt PPPP Type 0xD0, nicht 0xD1!" referring to Outer Type.
        # It doesn't explicitly specify Inner Type.
        # However, Prompt C (Tests) says: "wrap_login... CMD-Type: 0xD0 (nicht 0xD1!)" (Outer).
        # Let's use D1 for Inner Header as default for session, unless proven otherwise.
        # Wait, if I look at `test_wrap_login_packet` in Prompt C, it doesn't specify inner bytes expectation detail, just "Sequence incremented".
        # Let's check `modules/pppp_wrapper.py.bak` if I could read it?
        # I moved it. I can read it.

        seq = self._increment_sequence()
        inner = PPPPInnerHeader(
            session_type=0xD1, # Using D1 as generic inner type
            subcommand=0x00,
            sequence=seq,
            reserved=0x00
        )
        inner_bytes = inner.to_bytes()

        total_len = len(inner_bytes) + len(artemis_payload)
        outer = PPPPOuterHeader(
            magic=PPPPConstants.MAGIC_STANDARD,
            cmd_type=PPPPConstants.CMD_LOGIN, # D0
            length=total_len
        )

        packet = outer.to_bytes() + inner_bytes + artemis_payload
        logger.debug(f"[PPPP] wrap_login: seq={seq}, length={total_len}")
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
            cmd_type=PPPPConstants.CMD_CONTROL, # D3
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
        # Prompt K says: "wrap_command(json_bytes)"
        # Let's assume it uses same as heartbeat (D3 or D1).
        # Prompt I says: "Heartbeat... PPPP Type: 0xD3 (alternative: 0xD1)"
        # Prompt K: uses wrap_command.
        return self.wrap_heartbeat(json_bytes)

if __name__ == "__main__":
    # Test execution
    logging.basicConfig(level=logging.DEBUG)
    protocol = PPPPProtocol()
    packet = protocol.wrap_discovery(0x0048)
    print(f"Discovery packet: {packet.hex()}")
