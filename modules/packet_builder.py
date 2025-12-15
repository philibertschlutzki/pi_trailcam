import struct
import logging
import base64
from typing import Optional, Union

logger = logging.getLogger(__name__)

class ArtemisPacketBuilder:
    """
    Builder for PPPP/ARTEMIS login packets.
    Ensures correct structure and size for authentication.
    """

    @staticmethod
    def build_login_packet(token_str: str, sequence: int = 5, ble_seq: Optional[bytes] = None) -> bytes:
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

        Layer 4: Command Structure (8 bytes) - FIX #85
        ├─ Offset 16-19: 0x02000000 (LE) Command ID = 0x02 (Login)
        ├─ Offset 20-23: [BLE Seq]        Sequence from BLE (4 bytes)
        └─ Offset 24-27: [Token Len]      Token Length (4 bytes LE)

        Layer 5: Token Payload (Variable bytes)
        └─ Token bytes (UTF-8 encoded string)

        Args:
            token_str: The session token string.
            sequence: The PPPP/Artemis sequence number for the packet (Layer 2).
            ble_seq: The sequence bytes obtained from BLE (Layer 4).

        Returns:
            bytes: The constructed packet.
        """
        try:
            # --- Layer 5: Token Payload ---
            # FIX #78: Do not double-encode Base64.
            # The token from BLE is likely already Base64 string or the exact string required.
            token_payload = token_str.encode('utf-8')

            # Ensure null terminator? Some traces show it, some don't.
            # The packet builder previously added \x00. Let's keep it for now but NOT truncate.
            token_payload += b'\x00'
            payload_len = len(token_payload)

            # --- Layer 4: Command Structure (12 bytes) ---
            # 0x02000000 (LE) -> Command ID 2 (4 bytes)
            cmd_id = struct.pack('<I', 2)

            # Sequence (4 bytes) - From BLE or fallback
            if ble_seq and len(ble_seq) == 4:
                seq_field = ble_seq
            else:
                # Fallback to previous logic or simple default if not provided
                # Previous logic: subcmd(04) + prefix(00 01 00)
                # But Issue #85 says this should be the BLE sequence
                # Default to 0 if not provided (should be provided!)
                seq_field = b'\x00\x00\x00\x00'
                if ble_seq:
                     logger.warning(f"[PACKET BUILDER] Invalid BLE sequence length: {len(ble_seq)}")

            # Token Length (4 bytes LE)
            len_field = struct.pack('<I', payload_len)

            # Combine Layer 4: Command (4) + Sequence (4) + Length (4) = 12 bytes
            layer4 = cmd_id + seq_field + len_field

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
            logger.debug(f"[PACKET BUILDER] BLE Sequence: {seq_field.hex()}")

            return packet

        except Exception as e:
            logger.error(f"[PACKET BUILDER] Error building packet: {e}")
            raise
