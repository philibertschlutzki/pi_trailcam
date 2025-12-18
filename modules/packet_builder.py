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

        Layer 4: Command Structure (12 bytes) - FIX #85
        ├─ Offset 16-19: 0x02000000 (LE) Command ID = 0x02 (Login)
        ├─ Offset 20-27: [BLE Seq]        Sequence from BLE (8 bytes) - FIX #87
        └─ Offset 28-31: [Token Len]      Token Length (4 bytes LE)

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

            # Removed null terminator to match protocol spec
            payload_len = len(token_payload)

            # --- Layer 4: Command Structure ---
            # 0x02000000 (LE) -> Command ID 2 (4 bytes)
            cmd_id = struct.pack('<I', 2)

            # Sequence (4 bytes) - Fixed to 4 bytes LE
            if ble_seq and isinstance(ble_seq, bytes):
                if len(ble_seq) >= 4:
                    seq_field = ble_seq[:4]
                else:
                    seq_field = ble_seq.ljust(4, b'\x00')
            else:
                # Default to 0 if not provided
                seq_field = b'\x00' * 4
                if ble_seq:
                     logger.warning(f"[PACKET BUILDER] Invalid BLE sequence length: {len(ble_seq)}")

            # Token Length (4 bytes LE)
            len_field = struct.pack('<I', payload_len)

            # Combine Layer 4: Command (4) + Sequence (4) + Length (4) = 12 bytes
            layer4 = cmd_id + seq_field + len_field

            # --- Layer 3: Protocol Identifier (8 bytes) ---
            layer3 = b'ARTEMIS\x00'

            # --- Layer 2: ARTEMIS Wrapper (4 bytes) ---
            # FIX #89: Inner Header must be 4 bytes Big Endian
            # d1 03 [Seq 2 bytes BE]
            seq_bytes = struct.pack('>H', sequence)
            layer2 = b'\xd1\x03' + seq_bytes

            # --- Layer 1: PPPP Header ---
            # Magic F1, Type D0

            # Calculate total payload length (Layers 2 + 3 + 4 + 5)
            total_payload = layer2 + layer3 + layer4 + token_payload
            length_val = len(total_payload)

            # FIX #89: Big Endian Length per protocol analysis hex dump
            header = b'\xf1\xd0' + struct.pack('>H', length_val)

            packet = header + total_payload

            logger.debug(f"[PACKET BUILDER] Built login packet: {len(packet)} bytes (Payload len: {length_val})")
            logger.debug(f"[PACKET BUILDER] BLE Sequence: {seq_field.hex()}")

            return packet

        except Exception as e:
            logger.error(f"[PACKET BUILDER] Error building packet: {e}")
            raise
