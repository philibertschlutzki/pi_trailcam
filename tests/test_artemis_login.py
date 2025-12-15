import pytest
import asyncio
import struct
import json
from unittest.mock import MagicMock, AsyncMock, patch
from src.artemis_login import ArtemisLoginHandler

class MockSocket:
    def __init__(self):
        self.sent_packets = []
        self.mock_responses = []
        self.setsockopt = MagicMock()
        self.bind = MagicMock()
        self.setblocking = MagicMock()
        self.close = MagicMock()

    def sendto(self, data, addr):
        self.sent_packets.append((data, addr))

    def recv(self, bufsize):
        if self.mock_responses:
            return self.mock_responses.pop(0)
        raise BlockingIOError # Asyncio handles this

@pytest.fixture
def handler():
    return ArtemisLoginHandler(target_ip="192.168.1.100", target_port=40611)

@pytest.mark.asyncio
async def test_phase1_init_packet_format(handler):
    """Test Packet-Format: F1 E1 00 04 E1 00 00 01"""

    # Mock socket
    mock_sock = MockSocket()
    with patch('socket.socket', return_value=mock_sock):
        await handler.phase1_init()

    assert len(mock_sock.sent_packets) == 1
    packet, addr = mock_sock.sent_packets[0]

    expected = bytes.fromhex("F1 E1 00 04 E1 00 00 01")
    assert packet == expected
    assert addr == ("192.168.1.100", 40611)

@pytest.mark.asyncio
async def test_phase2_discovery_response_parsing(handler):
    """Test extracting UID from F1 41... response"""

    # Mock socket recv
    mock_sock = MockSocket()
    handler.sock = mock_sock # Manually assign socket

    # Construct Mock Response
    # F1 41 00 14 (20 bytes) + UID "LBCS-000000-CCCJJ" + nulls
    header = bytes.fromhex("F1 41 00 14")
    uid_str = "LBCS-000000-CCCJJ"
    payload = uid_str.encode('utf-8').ljust(20, b'\x00')
    response = header + payload

    with patch('socket.socket', return_value=mock_sock):
        future = asyncio.Future()
        future.set_result(response)

        with patch('asyncio.get_running_loop') as mock_loop_getter:
            mock_loop = MagicMock()
            mock_loop.sock_recv.return_value = future
            mock_loop_getter.return_value = mock_loop

            result = await handler.phase2_discover()

    assert result is True
    assert handler.device_uid == "LBCS-000000-CCCJJ"

@pytest.mark.asyncio
async def test_phase3_login_packet_construction(handler):
    """Test Login Packet Format"""
    handler.device_uid = "LBCS-TEST"
    handler.ble_token = "admin"
    handler.ble_sequence = 1

    mock_sock = MockSocket()
    handler.sock = mock_sock # Manually assign socket

    # Mock Response for Success
    # F1 D0 ... {"errorCode": 0}
    response_payload = json.dumps({"errorCode": 0}).encode('utf-8')
    # Inner: D1 00 00 00 (dummy)
    response = bytes.fromhex("F1 D0 00 20 00 00 00 00") + response_payload

    future = asyncio.Future()
    future.set_result(response)

    with patch('socket.socket', return_value=mock_sock):
        with patch('asyncio.get_running_loop') as mock_loop_getter:
            mock_loop = MagicMock()
            mock_loop.sock_recv.return_value = future
            mock_loop_getter.return_value = mock_loop

            result = await handler.phase3_login()

    assert result is True

    # Verify sent packet
    packet, _ = mock_sock.sent_packets[0]

    # Outer Header
    assert packet[0] == 0xF1
    assert packet[1] == 0xD0

    # Inner Header: D1 03 00 02
    assert packet[4] == 0xD1
    assert packet[5] == 0x03
    assert packet[6] == 0x00
    assert packet[7] == 0x02

    # Artemis Payload starts at 8
    artemis = packet[8:]
    assert artemis.startswith(b'ARTEMIS\x00')

    # Version 02 00 00 00
    assert artemis[8:12] == b'\x02\x00\x00\x00'

    # Seq Mystery 01 00 00 00 (LE 1)
    assert artemis[12:16] == b'\x01\x00\x00\x00'

    # Token Len 5
    assert artemis[16:20] == b'\x05\x00\x00\x00'

    # Token "admin"
    assert artemis[20:25] == b'admin'

@pytest.mark.asyncio
async def test_phase3_login_response_validation_failure(handler):
    """Test Login Failure (errorCode != 0)"""
    handler.device_uid = "LBCS-TEST"

    mock_sock = MockSocket()
    handler.sock = mock_sock # Manually assign socket

    response_payload = json.dumps({"errorCode": 1}).encode('utf-8')
    response = bytes.fromhex("F1 D0 00 20 00 00 00 00") + response_payload

    future = asyncio.Future()
    future.set_result(response)

    with patch('socket.socket', return_value=mock_sock):
        with patch('asyncio.get_running_loop') as mock_loop_getter:
            mock_loop = MagicMock()
            mock_loop.sock_recv.return_value = future
            mock_loop_getter.return_value = mock_loop

            result = await handler.phase3_login()

    assert result is False
