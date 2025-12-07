import unittest
from unittest.mock import MagicMock, patch
import time
from modules.camera_client import CameraClient, CameraState
import config

class TestCameraClient(unittest.TestCase):

    def setUp(self):
        self.client = CameraClient()

    @patch('modules.camera_client.socket.socket')
    @patch('modules.camera_client.time.time')
    @patch('modules.camera_client.time.sleep')
    def test_connect_with_retries_success(self, mock_sleep, mock_time, mock_socket):
        # Mock socket
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance

        # Setup mock for discovery_phase to return True immediately
        self.client.discovery_phase = MagicMock(return_value=True)

        # Mock time
        mock_time.side_effect = lambda: 100 + mock_time.call_count

        result = self.client.connect_with_retries()

        self.assertTrue(result)
        self.assertEqual(self.client.state, CameraState.CONNECTED)
        self.client.discovery_phase.assert_called()

    @patch('modules.camera_client.socket.socket')
    @patch('modules.camera_client.time.time')
    @patch('modules.camera_client.time.sleep')
    def test_connect_with_retries_fail_discovery(self, mock_sleep, mock_time, mock_socket):
        # Mock socket
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance

        # Setup mock for discovery_phase to return False (fail)
        self.client.discovery_phase = MagicMock(return_value=False)

        # Mock time to stay within limit
        # We need it to NOT exceed MAX_TOTAL_CONNECTION_TIME (60s)
        # So we return a constant value or slowly incrementing
        mock_time.return_value = 100

        # We expect it to retry MAX_CONNECTION_RETRIES times
        result = self.client.connect_with_retries()

        self.assertFalse(result)
        self.assertEqual(self.client.state, CameraState.CONNECTION_FAILED)
        self.assertEqual(self.client.discovery_phase.call_count, config.MAX_CONNECTION_RETRIES * len(config.DEVICE_PORTS))

    @patch('modules.camera_client.socket.socket')
    def test_discovery_phase_success(self, mock_socket):
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        self.client.sock = mock_sock_instance

        # Mock receive data
        mock_sock_instance.recvfrom.return_value = (b'response', ('192.168.1.1', 1234))

        result = self.client.discovery_phase()

        self.assertTrue(result)
        self.assertEqual(self.client.state, CameraState.DISCOVERED)

    @patch('modules.camera_client.socket.socket')
    def test_discovery_phase_timeout(self, mock_socket):
        import socket
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        self.client.sock = mock_sock_instance

        # Mock timeout
        mock_sock_instance.recvfrom.side_effect = socket.timeout

        result = self.client.discovery_phase()

        self.assertFalse(result)

    def test_login_requires_state(self):
        self.client.set_session_credentials('token', b'seq')

        # State is DISCONNECTED
        result = self.client.login()
        self.assertFalse(result)

        self.client._set_state(CameraState.CONNECTED)
        # Now it should try sending (mock send_packet if needed)
        with patch.object(self.client, 'send_packet', return_value=True):
            result = self.client.login()
            self.assertTrue(result)
            self.assertEqual(self.client.state, CameraState.AUTHENTICATED)

if __name__ == '__main__':
    unittest.main()
