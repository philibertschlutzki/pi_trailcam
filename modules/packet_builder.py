import struct
import logging
import base64
from typing import Optional

logger = logging.getLogger(__name__)

class ArtemisPacketBuilder:
    """
    Builder for PPPP/ARTEMIS login packets.
    Ensures correct structure and size (53 bytes) for authentication.
    """

    @staticmethod
    def build_login_packet(token_str: str, sequence: int = 5) -> bytes:
        """
        Builds a complete PPPP + ARTEMIS login packet.

        Packet Structure (53 bytes):
        Layer 1: PPPP Header (4 bytes)
        ├─ Offset 0:    0xf1              PPPP Magic
        ├─ Offset 1:    0xd0              Type (Login)
        └─ Offset 2-3:  0x0031 (LE)       Payload length = 49 bytes

        Layer 2: ARTEMIS Wrapper (4 bytes)
        ├─ Offset 4:    0xd1              ARTEMIS Marker
        └─ Offset 5-7:  0x000005 (BE)     Sequence counter

        Layer 3: Protocol Identifier (8 bytes)
        └─ Offset 8-15: "ARTEMIS\0"       Protocol string with null terminator

        Layer 4: Command Structure (9 bytes)
        ├─ Offset 16-19: 0x02000000 (LE) Command ID = 0x02 (Login)
        ├─ Offset 20:    0x04             Subcommand ID = 0x04 (Credentials)
        ├─ Offset 21-24: 0x00010019       Parameters (flags/length indicator)
        └─ Offset 25-27: 0x000000         Padding

        Layer 5: Token Payload (25 bytes)
        ├─ Offset 28-52: Base64-encoded token (24 bytes)
        └─ Offset 53:    0x00             Null terminator

        Args:
            token_str: The session token string (will be Base64 encoded).
            sequence: The sequence number for the packet (default 5).

        Returns:
            bytes: The constructed 53-byte packet.
        """
        try:
            # --- Layer 5: Token Payload ---
            # Token MUST be Base64-encoded
            token_bytes = token_str.encode('utf-8')
            token_b64 = base64.b64encode(token_bytes)

            # Ensure token fits in the 25-byte payload (24 bytes + null)
            # Pad with nulls to 24 bytes, then take first 24 bytes
            padded_token = token_b64.ljust(24, b'\x00')[:24]
            token_payload = padded_token + b'\x00' # 25 bytes

            # --- Layer 4: Command Structure (9 bytes) ---
            # 0x02000000 (LE) -> Command ID 2
            cmd_id = struct.pack('<I', 2)

            # Subcommand 0x04
            subcmd = b'\x04'

            # Parameters 00 01 00 19
            # 0x19 = 25 (Length of payload?)
            params = b'\x00\x01\x00\x19'

            # Padding 00 00 00
            padding = b'\x00\x00\x00'

            layer4 = cmd_id + subcmd + params + padding

            # --- Layer 3: Protocol Identifier (8 bytes) ---
            layer3 = b'ARTEMIS\x00'

            # --- Layer 2: ARTEMIS Wrapper (4 bytes) ---
            # d1 00 [Seq]
            seq_bytes = struct.pack('>H', sequence)
            layer2 = b'\xd1\x00' + seq_bytes

            # --- Layer 1: PPPP Header ---
            # Magic F1, Type D0, Length 49 (0x31)
            # struct.pack('>H', 49) -> 00 31
            header = b'\xf1\xd0' + struct.pack('>H', 49)

            packet = header + layer2 + layer3 + layer4 + token_payload

            # Validate size
            if len(packet) != 53:
                logger.error(f"[PACKET BUILDER] Packet size {len(packet)} != 53")

            return packet

        except Exception as e:
            logger.error(f"[PACKET BUILDER] Error building packet: {e}")
            raise
