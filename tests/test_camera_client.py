import unittest
from unittest.mock import MagicMock, patch
import socket
import struct
from modules.camera_client import CameraClient, CameraState
from modules.pppp_wrapper import PPPPWrapper
import config

class TestCameraClient(unittest.TestCase):

    def setUp(self):
        self.client = CameraClient()
        self.pppp_helper = PPPPWrapper() # To help generate mock packets

    @patch('modules.camera_client.socket.socket')
    @patch('modules.camera_client.time.time')
    @patch('modules.camera_client.time.sleep')
    def test_connect_with_retries_success(self, mock_sleep, mock_time, mock_socket):
        # Mock socket
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance

        # FIX: Mock getsockname to return a valid tuple
        mock_sock_instance.getsockname.return_value = ('0.0.0.0', 12345)

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

        # FIX: Mock getsockname to return a valid tuple
        mock_sock_instance.getsockname.return_value = ('0.0.0.0', 12345)

        # Setup mock for discovery_phase to return False (fail)
        self.client.discovery_phase = MagicMock(return_value=False)

        # Mock time to stay within limit
        mock_time.return_value = 100

        result = self.client.connect_with_retries()

        self.assertFalse(result)
        self.assertEqual(self.client.state, CameraState.CONNECTION_FAILED)

    @patch('modules.camera_client.socket.socket')
    def test_discovery_phase_success(self, mock_socket):
        mock_sock_instance = MagicMock()
        # Mock successful creation
        self.client.sock = mock_sock_instance
        self.client.active_port = 12345

        # Create valid PPPP Discovery ACK packet
        # Inner: D1, Sub=0x01 (ACK), Seq=1
        discovery_ack = self.pppp_helper.wrap_pppp(
            b'\x00\x00',
            outer_type=0xD1,
            inner_type=0xD1,
            subcommand=0x01
        )

        # Mock receive data
        mock_sock_instance.recvfrom.return_value = (discovery_ack, ('192.168.1.1', 1234))

        result = self.client.discovery_phase()

        self.assertTrue(result)
        self.assertEqual(self.client.state, CameraState.DISCOVERED)

        # Verify it sent a PPPP packet (checking start with 0xF1)
        args, _ = mock_sock_instance.sendto.call_args
        sent_packet = args[0]
        self.assertEqual(sent_packet[0], 0xF1)

    @patch('modules.camera_client.socket.socket')
    def test_discovery_phase_timeout(self, mock_socket):
        mock_sock_instance = MagicMock()
        self.client.sock = mock_sock_instance

        # Mock timeout
        mock_sock_instance.recvfrom.side_effect = socket.timeout

        result = self.client.discovery_phase()

        self.assertFalse(result)

    @patch('modules.camera_client.socket.socket')
    def test_login_success(self, mock_socket):
        mock_sock_instance = MagicMock()
        self.client.sock = mock_sock_instance

        self.client.set_session_credentials('token', b'seq')
        self.client._set_state(CameraState.CONNECTED)

        # Create valid PPPP Login ACK packet
        # Inner: D1, Sub=0x04 (ACK), Seq=10
        login_ack = self.pppp_helper.wrap_pppp(
            b'\x00\x00',
            outer_type=0xD1,
            inner_type=0xD1,
            subcommand=0x04
        )

        mock_sock_instance.recvfrom.return_value = (login_ack, ('192.168.1.1', 1234))

        result = self.client.login()

        self.assertTrue(result)
        self.assertEqual(self.client.state, CameraState.AUTHENTICATED)

        # Verify it sent something that looks like PPPP
        args, _ = mock_sock_instance.sendto.call_args
        sent_packet = args[0]
        self.assertEqual(sent_packet[0], 0xF1)

if __name__ == '__main__':
    unittest.main()
