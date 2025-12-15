import pytest
import socket
import logging
import time
from unittest.mock import MagicMock, patch, call
from modules.camera_client import CameraClient
from modules.protocol.pppp import PPPPProtocol

# Setup logging for tests
logging.basicConfig(level=logging.DEBUG)

class TestUDPDebug:

    @pytest.fixture
    def camera_client(self):
        client = CameraClient(camera_ip="192.168.1.100")
        client.sock = MagicMock(spec=socket.socket)
        # Mock gettimeout
        client.sock.gettimeout.return_value = 5.0
        # Set session token and sequence to bypass checks
        client.set_session_credentials("fake_token", b'\x01\x00\x00\x00', use_ble_dynamic=True)
        return client

    def test_pppp_validation_valid(self):
        """Test that valid PPPP packets pass validation."""
        protocol = PPPPProtocol()

        # Create a valid Login packet (0xD0)
        payload = b'ARTEMIS\x00' + b'\x02\x00\x00\x00' + b'\x04\x00' + b'token_data_1234567'
        packet = protocol.wrap_login(payload)

        assert protocol.validate_packet(packet) == True

    def test_pppp_validation_invalid_header(self):
        """Test that invalid PPPP header raises error."""
        protocol = PPPPProtocol()
        packet = b'\x00\x00\x00\x00' # Invalid magic

        with pytest.raises(ValueError, match="Invalid PPPP Header"):
            protocol.validate_packet(packet)

    def test_pppp_validation_invalid_length(self):
        """Test that invalid packet length raises error."""
        protocol = PPPPProtocol()
        # Header length says 4, but packet is longer
        packet = b'\xF1\xD0\x00\x04\xD1\x00\x00\x01\xFF\xFF'

        with pytest.raises(ValueError, match="Length mismatch"):
            protocol.validate_packet(packet)

    def test_pppp_validation_invalid_signature(self):
        """Test that invalid Artemis signature raises error."""
        protocol = PPPPProtocol()
        # Create a login packet with bad signature
        # Header (4) + Inner (4) + Sig (9) ... (BAD_SIG.\x00 is 9 bytes)
        # Inner: 4 bytes. Payload: 9 bytes. Total: 13 bytes.
        # Header Length should be 13 (0x0D)

        packet = b'\xF1\xD0\x00\x0D' + b'\xD1\x03\x00\x01' + b'BAD_SIG.\x00'

        with pytest.raises(ValueError, match="Invalid Artemis Signature"):
            protocol.validate_packet(packet)

    def test_port_fallback(self, camera_client):
        """Test that client falls back to port 59130 if 40611 fails."""

        # We need to simulate connect_with_retries logic.
        # Specifically checking the logic inside connect_with_retries where it tries fallback.
        # We can mock _try_login_on_port instead of the socket calls to make it easier.

        with patch.object(camera_client, '_create_socket', return_value=True), \
             patch.object(camera_client, '_discover_login_port', return_value=None), \
             patch.object(camera_client, '_send_init_packets', return_value=True), \
             patch.object(camera_client, 'start_heartbeat') as mock_heartbeat, \
             patch.object(camera_client, '_try_login_on_port') as mock_login:

            # Setup login side effects: First call (40611) False, Second call (59130) True
            mock_login.side_effect = [False, True]

            # Reduce delays for test speed
            with patch('time.sleep', return_value=None):
                result = camera_client.connect_with_retries()

            assert result == True
            # Verify calls
            # Expecting call with 40611
            # Then call with 59130
            # Note: The retry loop calls _create_socket, _discover..., _send_init...

            # Check calls to _try_login_on_port
            # First attempt in loop:
            # 1. 40611 -> Fail
            # 2. 59130 -> Success -> Return True

            mock_login.assert_has_calls([
                call(40611),
                call(59130)
            ])

            assert mock_heartbeat.called

    def test_logging_hex_dump_send(self, camera_client):
        """Verify that hex dumps are logged on send."""
        payload = b'\xF1\xD0\x00\x01'
        addr = ('192.168.1.100', 40611)

        # Mock the logger instance on the client
        camera_client.logger = MagicMock()

        camera_client.send_with_logging(payload, addr)

        # Check if logger.info was called with hex string "f1d00001" (no spaces in .hex())
        found = False
        for log_call in camera_client.logger.info.call_args_list:
            # Check for hex string representation
            if "f1d00001" in str(log_call) or "F1D00001" in str(log_call):
                found = True
                break
        assert found, "Hex dump not found in info logs"

    def test_logging_hex_dump_recv(self, camera_client):
        """Verify that hex dumps are logged on recv."""
        # Mock the logger instance on the client
        camera_client.logger = MagicMock()

        # Setup mock socket to return data
        camera_client.sock.recvfrom.return_value = (b'\xF1\xD1\x00\x01', ('192.168.1.1', 40611))

        data, addr = camera_client.recv_with_logging()

        assert data == b'\xF1\xD1\x00\x01'

        found = False
        for log_call in camera_client.logger.info.call_args_list:
            if "f1d10001" in str(log_call) or "F1D10001" in str(log_call):
                found = True
                break
        assert found, "Hex dump not found in info logs"

    def test_recv_timeout_logging(self, camera_client):
        """Verify timeout logging behavior."""
        camera_client.sock.recvfrom.side_effect = socket.timeout

        with patch.object(camera_client.logger, 'warning') as mock_warning:
            data, addr = camera_client.recv_with_logging(timeout=0.1)

            assert data is None
            assert mock_warning.called
            assert "UDP TIMEOUT" in str(mock_warning.call_args)
