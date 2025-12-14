# tests/test_camera_client.py
import unittest
from unittest.mock import MagicMock, patch
import socket
import struct
from modules.camera_client import CameraClient, CameraState
from modules.protocol.pppp import PPPPProtocol
import config

class TestCameraClient(unittest.TestCase):

    def setUp(self):
        self.client = CameraClient()
        self.pppp_helper = PPPPProtocol() # To help generate mock packets

    @patch('modules.camera_client.socket.socket')
    @patch('modules.camera_client.time.time')
    @patch('modules.camera_client.time.sleep')
    def test_connect_with_retries_success(self, mock_sleep, mock_time, mock_socket):
        # Mock socket
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance

        # FIX: Mock getsockname to return a valid tuple
        mock_sock_instance.getsockname.return_value = ('0.0.0.0', 12345)

        # Mock init packets success
        self.client._send_init_packets = MagicMock(return_value=True)
        # Mock login success
        self.client._try_login_on_port = MagicMock(return_value=True)

        # Mock time
        mock_time.side_effect = lambda: 100 + mock_time.call_count

        result = self.client.connect_with_retries()

        self.assertTrue(result)
        self.assertEqual(self.client.state, CameraState.CONNECTED)
        self.client._send_init_packets.assert_called()
        self.client._try_login_on_port.assert_called()

    @patch('modules.camera_client.socket.socket')
    @patch('modules.camera_client.time.time')
    @patch('modules.camera_client.time.sleep')
    def test_connect_with_retries_fail_login(self, mock_sleep, mock_time, mock_socket):
        # Mock socket
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance

        # FIX: Mock getsockname to return a valid tuple
        mock_sock_instance.getsockname.return_value = ('0.0.0.0', 12345)

        # Mock init packets success
        self.client._send_init_packets = MagicMock(return_value=True)
        # Mock login failure
        self.client._try_login_on_port = MagicMock(return_value=False)

        # Mock time to stay within limit
        mock_time.return_value = 100

        result = self.client.connect_with_retries()

        self.assertFalse(result)
        # Final state depends on implementation, usually CONNECTION_FAILED
        self.assertEqual(self.client.state, CameraState.CONNECTION_FAILED)

    @patch('modules.camera_client.socket.socket')
    def test_login_success(self, mock_socket):
        mock_sock_instance = MagicMock()
        self.client.sock = mock_sock_instance

        self.client.set_session_credentials('token', b'seq')
        # We need a state where login is allowed (e.g., INITIALIZING or CONNECTING)
        self.client._set_state(CameraState.CONNECTING)

        # Mock response packet for login
        # Outer(F1, D0, len=4) + Inner(D1, 04, Seq=1)
        # PPPPInnerHeader(D1, 04, 1) -> 4 bytes
        # Payload empty
        # PPPPProtocol expects >BBH for inner (3 bytes + sequence)

        # Manually construct response packet
        # F1 D0 00 04 (Outer) + D1 04 00 01 (Inner)
        login_ack = b'\xf1\xd0\x00\x04\xd1\x04\x00\x01'

        mock_sock_instance.recvfrom.return_value = (login_ack, ('192.168.1.1', 1234))

        # Use _try_login_on_port directly as login() calls it
        result = self.client._try_login_on_port(1234)

        self.assertTrue(result)
        self.assertEqual(self.client.state, CameraState.AUTHENTICATED)

if __name__ == '__main__':
    unittest.main()
