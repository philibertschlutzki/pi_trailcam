import unittest
from unittest.mock import MagicMock, patch
import struct
import time
from modules.camera_client import CameraClient

class TestCameraLogin(unittest.TestCase):
    """
    Test different authentication scenarios.
    """

    def setUp(self):
        self.camera = CameraClient("192.168.1.1")
        self.camera.sock = MagicMock()
        # Prevent heartbeat thread from actually doing much or verify it separately
        # But since we mock sock, it's fine. We just need to find the right call.

    def tearDown(self):
        self.camera.close()

    def test_extracted_token(self):
        """Test with real BLE-extracted token (should work)."""
        token = "I3mbwVIxJQgnSB9GJKNk5Bvv/y+g8+MX/HVCMnCqyUo="
        sequence = b'\x2b\x00\x00\x00'

        self.camera.set_session_credentials(token, sequence)

        # Mock successful response
        self.camera.sock.recvfrom.return_value = (b'response', ('192.168.1.1', 40611))

        result = self.camera.login()
        self.assertTrue(result)

        # Verify payload construction
        # We search through all calls to sendto
        found_token = False
        found_sequence = False

        for call in self.camera.sock.sendto.call_args_list:
            sent_data = call[0][0]
            if token.encode('ascii') in sent_data:
                found_token = True
            if sequence in sent_data:
                found_sequence = True

        self.assertTrue(found_token, "Token not found in any sent packet")
        self.assertTrue(found_sequence, "Sequence not found in any sent packet")

    def test_hardcoded_token_not_used(self):
        """Test that we are NOT using the old hardcoded token."""
        token = "I3mbwVIxJQgnSB9GJKNk5Bvv/y+g8+MX/HVCMnCqyUo="
        sequence = b'\x2b\x00\x00\x00'

        self.camera.set_session_credentials(token, sequence)
        self.camera.sock.recvfrom.return_value = (b'response', ('192.168.1.1', 40611))

        self.camera.login()

        # Old token from background
        old_token = "MzlB36X/IVo8ZzI5rG9j1w=="

        for call in self.camera.sock.sendto.call_args_list:
            sent_data = call[0][0]
            self.assertNotIn(old_token.encode('ascii'), sent_data)

    def test_sequence_increment(self):
        """Test with incremented sequence (should work)."""
        token = "I3mbwVIxJQgnSB9GJKNk5Bvv/y+g8+MX/HVCMnCqyUo="
        sequence = b'\x2c\x00\x00\x00' # Incremented 2b -> 2c

        self.camera.set_session_credentials(token, sequence)
        self.camera.sock.recvfrom.return_value = (b'response', ('192.168.1.1', 40611))

        self.camera.login()

        found_sequence = False
        for call in self.camera.sock.sendto.call_args_list:
            sent_data = call[0][0]
            if sequence in sent_data:
                found_sequence = True

        self.assertTrue(found_sequence, "Incremented sequence not found in any sent packet")

    def test_missing_credentials(self):
        """Test login fails or raises without credentials."""
        # Ensure credentials are not set
        self.camera.session_token = None
        self.camera.sequence_bytes = None

        result = self.camera.login()
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
