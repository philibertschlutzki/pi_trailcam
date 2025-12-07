import unittest
import struct
import logging
from modules.pppp_wrapper import PPPPWrapper

class TestPPPPWrapper(unittest.TestCase):
    def setUp(self):
        # Configure a dummy logger to avoid console spam during tests
        logging.basicConfig(level=logging.CRITICAL)
        self.wrapper = PPPPWrapper()

    def test_wrap_discovery_known_packet(self):
        """Test wrapping a discovery packet against a known TCPDump capture."""
        # Known packet from TCPDump: f1d10006d1000001001b
        # Outer: F1 D1 00 06
        # Inner: D1 00 00 01
        # Payload: 00 1B

        # Reset sequence to 1 to match the capture
        self.wrapper.reset_sequence(1)

        artemis_seq = 0x001B
        packet = self.wrapper.wrap_discovery(artemis_seq)

        expected_hex = "f1d10006d1000001001b"
        self.assertEqual(packet.hex(), expected_hex)

        # Verify headers specifically
        self.assertEqual(packet[0], 0xF1) # Magic
        self.assertEqual(packet[1], 0xD1) # Outer Type
        self.assertEqual(struct.unpack('>H', packet[2:4])[0], 6) # Length (4+2)
        self.assertEqual(packet[4], 0xD1) # Inner Type
        self.assertEqual(packet[5], 0x00) # Subcommand (Discovery)
        self.assertEqual(struct.unpack('>H', packet[6:8])[0], 1) # PPPP Seq

    def test_sequence_increment(self):
        """Test that PPPP sequence number increments correctly."""
        self.wrapper.reset_sequence(1)

        # First packet (Seq 1)
        pkt1 = self.wrapper.wrap_discovery(0x001B)
        seq1 = struct.unpack('>H', pkt1[6:8])[0]
        self.assertEqual(seq1, 1)

        # Second packet (Seq 2)
        pkt2 = self.wrapper.wrap_discovery(0x001B)
        seq2 = struct.unpack('>H', pkt2[6:8])[0]
        self.assertEqual(seq2, 2)

        # Third packet (Seq 3)
        pkt3 = self.wrapper.wrap_heartbeat(0x001B)
        seq3 = struct.unpack('>H', pkt3[6:8])[0]
        self.assertEqual(seq3, 3)

    def test_wrap_login(self):
        """Test wrapping a login packet."""
        # Create a dummy payload of 38 bytes
        dummy_payload = b'A' * 38

        self.wrapper.reset_sequence(10)
        packet = self.wrapper.wrap_login(dummy_payload)

        # Length should be 38 (payload) + 4 (inner header) = 42 (0x2A)
        expected_len = 42

        # Verify length in outer header
        packet_len = struct.unpack('>H', packet[2:4])[0]
        self.assertEqual(packet_len, expected_len)

        # Verify Subcommand (0x03 for Login)
        self.assertEqual(packet[5], 0x03)

        # Verify Seq (10)
        seq = struct.unpack('>H', packet[6:8])[0]
        self.assertEqual(seq, 10)

    def test_wrap_heartbeat(self):
        """Test wrapping a heartbeat packet."""
        self.wrapper.reset_sequence(5)
        packet = self.wrapper.wrap_heartbeat(0x0020)

        # Heartbeat uses Control type (0xD3)
        self.assertEqual(packet[1], 0xD3) # Outer
        self.assertEqual(packet[4], 0xD3) # Inner

        # Subcommand 0x01
        self.assertEqual(packet[5], 0x01)

        # Payload size is 4 bytes (2 seq + 2 padding)
        # Total length = 4 + 4 = 8
        packet_len = struct.unpack('>H', packet[2:4])[0]
        self.assertEqual(packet_len, 8)

    def test_unwrap_pppp(self):
        """Test unwrapping a packet (Round Trip)."""
        original_payload = b'\x12\x34\x56'
        self.wrapper.reset_sequence(100)

        # Wrap it
        packet = self.wrapper.wrap_pppp(
            original_payload,
            outer_type=0xD1,
            inner_type=0xD1,
            subcommand=0x01
        )

        # Unwrap it
        parsed = self.wrapper.unwrap_pppp(packet)

        self.assertEqual(parsed['outer_magic'], 0xF1)
        self.assertEqual(parsed['outer_type'], 0xD1)
        self.assertEqual(parsed['inner_type'], 0xD1)
        self.assertEqual(parsed['subcommand'], 0x01)
        self.assertEqual(parsed['pppp_seq'], 100)
        self.assertEqual(parsed['payload'], original_payload)

        # Check length
        expected_len = 4 + 3 # Inner header + payload
        self.assertEqual(parsed['length'], expected_len)

    def test_unwrap_too_short(self):
        """Test unwrapping a packet that is too short."""
        short_packet = b'\xF1\xD1\x00\x01' # 4 bytes
        with self.assertRaises(ValueError):
            self.wrapper.unwrap_pppp(short_packet)

if __name__ == '__main__':
    unittest.main()
