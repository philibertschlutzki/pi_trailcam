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
async def test_phase3_login_pppp_response_success(handler):
    """Test Login Success with PPPP-Wrapped Response"""
    handler.device_uid = "LBCS-TEST"
    handler.ble_token = "admin"
    handler.ble_sequence = 1

    mock_sock = MockSocket()
    handler.sock = mock_sock # Manually assign socket

    # Mock Response for Success
    # F1 D0 ... {"errorCode": 0, "result": 0}
    response_payload = json.dumps({"errorCode": 0, "result": 0}).encode('utf-8')
    # Inner: D1 00 00 00 (dummy) - wait, my new implementation expects payload at offset 4 if PPPP
    # New logic: data[0] = F1, data[1] = type, data[2-3] = len, data[4:] = payload

    # Outer Header: F1 D0 00 1C (28 bytes)
    # Payload = response_payload
    length = len(response_payload)
    response = struct.pack('>BBH', 0xF1, 0xD0, length) + response_payload

    # To simulate new logic's behavior exactly, I should verify what happens if payload starts at offset 4.
    # The new logic for PPPP:
    # magic = data[0]
    # pkt_type = data[1]
    # length = int.from_bytes(data[2:4], 'big')
    # payload = data[4:]
    # And tries to json decode payload.

    future = asyncio.Future()
    future.set_result(response)

    with patch('socket.socket', return_value=mock_sock):
        with patch('asyncio.get_running_loop') as mock_loop_getter:
            mock_loop = MagicMock()
            mock_loop.sock_recv.return_value = future
            mock_loop_getter.return_value = mock_loop

            result = await handler.phase3_login()

    assert result is True

@pytest.mark.asyncio
async def test_phase3_login_direct_json_response_success(handler):
    """Test Login Success with Direct JSON Response"""
    handler.device_uid = "LBCS-TEST"
    handler.ble_token = "admin"
    handler.ble_sequence = 1

    mock_sock = MockSocket()
    handler.sock = mock_sock # Manually assign socket

    # Mock Response for Success: Direct JSON
    response_payload = json.dumps({"errorCode": 0, "result": 0, "cmdId": 0}).encode('utf-8')

    future = asyncio.Future()
    future.set_result(response_payload)

    with patch('socket.socket', return_value=mock_sock):
        with patch('asyncio.get_running_loop') as mock_loop_getter:
            mock_loop = MagicMock()
            mock_loop.sock_recv.return_value = future
            mock_loop_getter.return_value = mock_loop

            result = await handler.phase3_login()

    assert result is True

@pytest.mark.asyncio
async def test_phase3_login_response_validation_failure(handler):
    """Test Login Failure (errorCode != 0)"""
    handler.device_uid = "LBCS-TEST"

    mock_sock = MockSocket()
    handler.sock = mock_sock # Manually assign socket

    response_payload = json.dumps({"errorCode": 1, "result": 1}).encode('utf-8')

    # Test with direct JSON failure
    future = asyncio.Future()
    future.set_result(response_payload)

    with patch('socket.socket', return_value=mock_sock):
        with patch('asyncio.get_running_loop') as mock_loop_getter:
            mock_loop = MagicMock()
            mock_loop.sock_recv.return_value = future
            mock_loop_getter.return_value = mock_loop

            result = await handler.phase3_login()

    assert result is False
