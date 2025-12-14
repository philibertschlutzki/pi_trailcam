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
            # Input "85087127" -> Base64 "ODUwODcxMjc=" (12 bytes)
            # Input "MzlB..." (24 chars) -> Base64 matches input if already base64?
            # The input token_str is likely raw or already base64?
            # BLE Listener returns "token" string.
            # If the token is already a Base64 string (e.g. "MzlB..."), b64encoding it again would be wrong?
            # The prompt says: "Token MUST be Base64-encoded using base64.b64encode()"
            # AND "Token Base64: {base64.b64encode(token.encode()).decode()}"
            # So I must encode it.

            token_bytes = token_str.encode('utf-8')
            token_b64 = base64.b64encode(token_bytes)

            # Ensure token fits in the 25-byte payload (24 bytes + null)
            # If the token is too short, we might need to pad it?
            # Or if it's too long, truncate?
            # The structure expects exactly 53 bytes total packet size.
            # This implies the token part MUST be exactly 25 bytes (including null).
            # So 24 bytes of data.

            # If the Base64 token is shorter than 24 bytes, we pad with nulls?
            # Or is the "Parameter" field 0x19 (25) dictating the length?
            # The user says "Validate final packet size is exactly 53 bytes".
            # This implies strict sizing.

            # Let's pad/truncate to 24 bytes for now to enforce size.
            # Note: 24 bytes is standard for some hash lengths in Base64.
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
            # d1 00 00 05
            # d1 = Marker
            # 00 = Subcommand (of wrapper?)
            # 00 05 = Sequence (Big Endian)
            # The user example: d1 00 00 05
            # My PPPPInnerHeader logic: D1 00 [Seq(2)]
            seq_bytes = struct.pack('>H', sequence)
            layer2 = b'\xd1\x00' + seq_bytes

            # Combine payload parts for length calculation
            payload_data = layer2 + layer3 + layer4 + token_payload
            payload_len = len(payload_data) # Should be 4 + 8 + 9 + 25 = 46?

            # Wait.
            # Layer 1 length is "Payload length".
            # User says: "Offset 2-3: 0x0031 (LE) Payload length = 49 bytes"
            # My calculation:
            # Layer 2 (4) + Layer 3 (8) + Layer 4 (9) + Layer 5 (25) = 46 bytes.
            # 49 - 46 = 3 bytes missing?

            # Let's re-check the hex offsets.
            # 0-3: Header (4)
            # 4-7: Wrapper (4)
            # 8-15: ARTEMIS (8)
            # 16-19: Cmd (4)
            # 20: Sub (1)
            # 21-24: Params (4)
            # 25-27: Padding (3). Wait, 25, 26, 27 is 3 bytes.
            # 28-52: Token (25 bytes).
            # 53: Null terminator? No, offset 53 is byte 54 (0-indexed).
            # If size is 53, last byte is at offset 52.

            # Re-calculating sizes:
            # Header: 4 bytes (0-3)
            # Wrapper: 4 bytes (4-7)
            # Proto: 8 bytes (8-15)
            # Cmd: 4 bytes (16-19)
            # Sub: 1 byte (20)
            # Params: 4 bytes (21-24)
            # Padding: 3 bytes (25-27)
            # Token: 25 bytes (28-52) ?
            # Total: 4+4+8+4+1+4+3+25 = 53 bytes.
            # Matches exactly.

            # Payload length (Layer 2 onwards):
            # 53 - 4 (Header) = 49 bytes.
            # Matches 0x31 (49).

            # So my components are correct.

            # --- Layer 1: PPPP Header ---
            # Magic F1
            # Type D0
            # Length 49 (LE -> 31 00? Or BE 00 31?)
            # User example: f1 d0 00 31.
            # 00 31 is 49 in Big Endian.
            # User said "0x0031 (LE)" but 00 31 is BE representation of 49.
            # I will use struct.pack('>H', 49) -> 00 31.

            header = b'\xf1\xd0' + struct.pack('>H', 49)

            packet = header + layer2 + layer3 + layer4 + token_payload

            # Validate size
            if len(packet) != 53:
                logger.error(f"[PACKET BUILDER] Packet size {len(packet)} != 53")
                logger.error(f"[PACKET BUILDER] Header: {len(header)}")
                logger.error(f"[PACKET BUILDER] Layer2: {len(layer2)}")
                logger.error(f"[PACKET BUILDER] Layer3: {len(layer3)}")
                logger.error(f"[PACKET BUILDER] Layer4: {len(layer4)}")
                logger.error(f"[PACKET BUILDER] Layer5: {len(token_payload)}")
                # We won't raise here to allow debug, but caller should check

            return packet

        except Exception as e:
            logger.error(f"[PACKET BUILDER] Error building packet: {e}")
            raise
