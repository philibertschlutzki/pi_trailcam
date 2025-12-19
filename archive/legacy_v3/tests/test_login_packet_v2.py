import sys
import os
import struct
import unittest

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.packet_builder import ArtemisPacketBuilder

class TestLoginPacketV2(unittest.TestCase):
    def test_build_login_packet_structure(self):
        token = "test_token"
        sequence = 3
        # Dummy BLE seq
        ble_seq = b'\x00\x00\x00\x00'

        packet = ArtemisPacketBuilder.build_login_packet(token, sequence, ble_seq)

        # 1. Outer Header: F1 D0 [Len BE]
        self.assertEqual(packet[0], 0xF1)
        self.assertEqual(packet[1], 0xD0)

        payload_len = len(packet) - 4
        # Check Length BE
        header_len = struct.unpack('>H', packet[2:4])[0]
        self.assertEqual(header_len, payload_len, "Outer Header Length mismatch")

        # 2. Inner Header: D1 03 [Seq BE]
        # Should be 4 bytes
        inner_header = packet[4:8]
        self.assertEqual(inner_header[0], 0xD1)
        self.assertEqual(inner_header[1], 0x03)

        inner_seq = struct.unpack('>H', inner_header[2:4])[0]
        self.assertEqual(inner_seq, sequence, "Inner Sequence mismatch")

        # 3. Layer 3: ARTEMIS\x00
        layer3 = packet[8:16]
        self.assertEqual(layer3, b'ARTEMIS\x00')

        # 4. Layer 4: Command
        # 02 00 00 00 (Cmd ID LE)
        cmd_id = struct.unpack('<I', packet[16:20])[0]
        self.assertEqual(cmd_id, 2)

        # BLE Seq (4 bytes)
        # Ble Seq passed was b'\x00...'.
        # Wait, build_login_packet handles ble_seq.
        # If ble_seq provided, it uses it.

        # Token Len (LE)
        # Offset 20-23: Seq
        # Offset 24-27: Token Len
        token_len = struct.unpack('<I', packet[24:28])[0]
        self.assertEqual(token_len, len(token))

        # 5. Layer 5: Token
        token_payload = packet[28:]
        self.assertEqual(token_payload.decode('utf-8'), token)

        print("\nLogin Packet V2 Structure Verified Successfully")
        print(f"Packet Hex: {packet.hex()}")

if __name__ == "__main__":
    unittest.main()
