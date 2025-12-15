import struct
import logging
import base64
from typing import Optional

logger = logging.getLogger(__name__)

class ArtemisPacketBuilder:
    """
    Builder for PPPP/ARTEMIS login packets.
    Ensures correct structure and size for authentication.
    """

    @staticmethod
    def build_login_packet(token_str: str, sequence: int = 5) -> bytes:
        """
        Builds a complete PPPP + ARTEMIS login packet.

        Packet Structure (Dynamic Length):
        Layer 1: PPPP Header (4 bytes)
        ├─ Offset 0:    0xf1              PPPP Magic
        ├─ Offset 1:    0xd0              Type (Login)
        └─ Offset 2-3:  [Payload Len]     Payload length (Layer 2+3+4+5)

        Layer 2: ARTEMIS Wrapper (4 bytes)
        ├─ Offset 4:    0xd1              ARTEMIS Marker
        ├─ Offset 5:    0x03              Subcommand (0x03 for Login Request) - FIX #78
        └─ Offset 6-7:  [Sequence]        Sequence counter (Big Endian)

        Layer 3: Protocol Identifier (8 bytes)
        └─ Offset 8-15: "ARTEMIS\0"       Protocol string with null terminator

        Layer 4: Command Structure (9 bytes)
        ├─ Offset 16-19: 0x02000000 (LE) Command ID = 0x02 (Login)
        ├─ Offset 20:    0x04             Subcommand ID = 0x04 (Credentials)
        ├─ Offset 21-24: 0x00010019       Parameters (flags/length indicator)
        └─ Offset 25-27: 0x000000         Padding

        Layer 5: Token Payload (Variable bytes)
        └─ Token bytes (UTF-8 encoded string)

        Args:
            token_str: The session token string.
            sequence: The sequence number for the packet.

        Returns:
            bytes: The constructed packet.
        """
        try:
            # --- Layer 5: Token Payload ---
            # FIX #78: Do not double-encode Base64.
            # The token from BLE is likely already Base64 string or the exact string required.
            # Also, do NOT truncate to 24 bytes.
            token_payload = token_str.encode('utf-8')

            # Ensure null terminator? Some traces show it, some don't.
            # The packet builder previously added \x00. Let's keep it for now but NOT truncate.
            token_payload += b'\x00'

            # --- Layer 4: Command Structure (9 bytes) ---
            # 0x02000000 (LE) -> Command ID 2
            cmd_id = struct.pack('<I', 2)

            # Subcommand 0x04
            subcmd = b'\x04'

            # Parameters 00 01 00 19
            # The 0x19 (25) likely referred to the fixed length 25.
            # We should probably update this if the token length changes.
            # However, for now, let's keep it fixed or try to calculate it?
            # 0x00 01 [00 19] -> Maybe 00 19 is length?
            # If so, it should be len(token_payload).
            # Let's try to update it to match payload length.
            # 2 bytes unknown (00 01), 2 bytes length?
            # Or 4 bytes parameters?
            # Given the previous code hardcoded it, and we don't know for sure,
            # let's try to set the last byte to the length if it's small enough.

            payload_len = len(token_payload)
            # Encode payload length into the parameters?
            # The previous code had 0x19 (25).
            # If we send a longer token, maybe we need to update this.
            # Let's assume the last byte is length.
            # But if length > 255?
            # Let's try keeping it as is for now, but if it fails, this is a suspect.
            # Actually, let's look at the Android trace "00 00 ?? ??" (Token Length).
            # The trace said: "?? ?? ?? ?? // Token Length"
            # My code had "00 01 00 19".
            # If I assume the last 4 bytes before token are length/padding?
            # Layer 4 has 9 bytes.
            # cmd (4) + sub (1) + params (4).

            # Let's trust the "VERMUTUNG" structure from the issue which had "Token Length" field.
            # 02 00 00 00 (Version/Cmd)
            # ?? ?? ?? ?? (Mystery/Seq)
            # ?? ?? ?? ?? (Token Length)

            # This contradicts my Layer 4 structure.
            # My Layer 4: Cmd(4) + Sub(1) + Params(4).

            # If the Android trace is correct (F1 D0 ... ARTEMIS ... 02 00 00 00 ...),
            # Then after ARTEMIS (8 bytes), we have:
            # 02 00 00 00
            # [4 bytes mystery]
            # [4 bytes length?]

            # Previous code:
            # cmd_id (4) + subcmd (1) + params (4) = 9 bytes.
            # 02 00 00 00 + 04 + 00 01 00 19.

            # This looks like it was reverse engineered from a specific packet.
            # If I want to support variable length, I should probably update the 0x19.
            # Let's update the last byte to match payload length.

            param_prefix = b'\x00\x01\x00'
            param_len = struct.pack('B', payload_len) # Assuming < 256
            params = param_prefix + param_len

            # Padding 00 00 00 (3 bytes)
            padding = b'\x00\x00\x00'

            layer4 = cmd_id + subcmd + params + padding

            # --- Layer 3: Protocol Identifier (8 bytes) ---
            layer3 = b'ARTEMIS\x00'

            # --- Layer 2: ARTEMIS Wrapper (4 bytes) ---
            # FIX #78: Subcommand 0x03 (Login Request)
            # d1 03 [Seq]
            seq_bytes = struct.pack('>H', sequence)
            layer2 = b'\xd1\x03' + seq_bytes

            # --- Layer 1: PPPP Header ---
            # Magic F1, Type D0

            # Calculate total payload length (Layers 2 + 3 + 4 + 5)
            total_payload = layer2 + layer3 + layer4 + token_payload
            length_val = len(total_payload)

            header = b'\xf1\xd0' + struct.pack('>H', length_val)

            packet = header + total_payload

            logger.debug(f"[PACKET BUILDER] Built login packet: {len(packet)} bytes (Payload len: {length_val})")
            logger.debug(f"[PACKET BUILDER] Token payload len: {len(token_payload)}")

            return packet

        except Exception as e:
            logger.error(f"[PACKET BUILDER] Error building packet: {e}")
            raise
