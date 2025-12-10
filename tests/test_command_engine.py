# tests/test_command_engine.py
import pytest
import asyncio
import socket
import json
import threading
from modules.protocol.pppp import PPPPProtocol
from modules.command_engine import CommandEngine
from tests.mock_camera_full import MockCamera

class MockCameraCommand(MockCamera):
    def handle_packet(self, sock, data, addr):
        if len(data) < 2: return
        magic = data[0]
        cmd = data[1]

        if magic != 0xF1: return

        # Command/Heartbeat is D3 or D1
        if cmd in [0xD3, 0xD1]:
            # Try to decode payload
            # Skip 9 bytes?
            try:
                json_part = data[9:].decode('utf-8', errors='ignore').rstrip('\x00')
                payload = json.loads(json_part)

                cmd_id = payload.get("cmdId")

                if cmd_id == 512: # Get Device Info
                    resp_payload = {
                        "cmdId": 512,
                        "deviceType": "KJK230",
                        "firmwareVersion": "1.0.0",
                        "modelName": "TrailCam"
                    }
                    self.send_json_response(sock, addr, resp_payload)
                else:
                    # Echo back
                    self.send_json_response(sock, addr, payload)
            except:
                pass

    def send_json_response(self, sock, addr, json_obj):
        payload = json.dumps(json_obj).encode('utf-8')
        # Wrap in PPPP F1 D3 ...
        # Simplified wrapper
        resp = bytearray([0xF1, 0xD3])
        # Length 2 bytes
        length = 5 + len(payload)
        resp.extend(length.to_bytes(2, 'big'))
        # Inner: D1 00 00 00 00
        resp.extend(b'\xD1\x00\x00\x00\x00')
        resp.extend(payload)

        sock.sendto(resp, addr)

@pytest.fixture
def mock_command_camera():
    import time
    # Retry logic if port is busy
    max_retries = 3
    mock = None
    for i in range(max_retries):
        try:
            mock = MockCameraCommand()
            break
        except OSError:
            if i == max_retries - 1:
                raise
            time.sleep(1.0)

    thread = threading.Thread(target=mock.run, daemon=True)
    thread.start()
    yield mock
    mock.running = False
    time.sleep(0.1)

@pytest.mark.asyncio
async def test_command_execution(mock_command_camera):
    camera_ip = "127.0.0.1"
    pppp = PPPPProtocol()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 0))
    sock.setblocking(False)

    engine = CommandEngine(camera_ip, pppp, sock)

    # Send command 512
    # Mock camera listens on 40611
    info = await engine.get_device_info()

    assert info["cmdId"] == 512
    assert info["deviceType"] == "KJK230"

    sock.close()
