# tests/test_full_session.py
import pytest
import socket
import asyncio
import json
import threading
from modules.discovery import DiscoveryPhase
from modules.login_phase import LoginPhase
from modules.heartbeat import HeartbeatManager
from modules.protocol.pppp import PPPPProtocol
from modules.artemis_login import ArtemisLogin
from tests.mock_camera_full import MockCamera

# Enhanced Mock Camera to handle Login
class MockCameraFullSession(MockCamera):
    def handle_packet(self, sock, data, addr):
        port = sock.getsockname()[1]
        if len(data) < 2: return

        magic = data[0]
        cmd = data[1]

        if magic != 0xF1:
            return

        if port == 32108:
            if cmd == 0xD1: # Discovery
                 # Respond Phase 1
                 payload = b'\x00' * 60
                 device_id = b'MOCK_DEVICE_ID_12345'
                 payload = device_id + payload[20:]
                 resp = bytearray([0xF1, 0xDD])
                 resp.extend(b'\x00\x3C') # Length 60
                 resp.extend(payload)
                 sock.sendto(resp, addr)

        elif port == 40611:
            if cmd == 0x41: # Phase 2
                sock.sendto(data, addr)
            elif cmd == 0x42: # Phase 3
                sock.sendto(data, addr)
            elif cmd == 0xD0: # Login
                # Assume Success
                # Respond with F1 D0 ...
                sock.sendto(data, addr) # Echo back as success
            elif cmd == 0xD3: # Heartbeat / Command
                # Respond
                sock.sendto(data, addr)

@pytest.fixture
def mock_session_camera():
    mock = MockCameraFullSession()
    thread = threading.Thread(target=mock.run, daemon=True)
    thread.start()
    yield mock
    mock.running = False

@pytest.mark.asyncio
async def test_discovery_to_login_flow(mock_session_camera):
    camera_ip = "127.0.0.1"
    artemis_seq = 0x0048
    token = json.dumps({"ret": 0, "ssid": "TEST"})

    pppp = PPPPProtocol()

    # 1. Discovery
    discovery = DiscoveryPhase(camera_ip, artemis_seq, pppp)
    discovery_result = await discovery.execute()
    assert discovery_result["success"]

    # 2. Login
    artemis_login = ArtemisLogin(token, artemis_seq, discovery_result["device_id"])
    login = LoginPhase(camera_ip, artemis_login, pppp)
    login_result = await login.execute()
    assert login_result["success"]

    # 3. Heartbeat
    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    hb = HeartbeatManager(camera_ip, pppp, socket_obj)

    task = asyncio.create_task(hb.start(interval_sec=0.5)) # Faster for test

    await asyncio.sleep(1.2) # Allow 2 heartbeats

    assert hb.missed_heartbeats == 0
    await hb.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
