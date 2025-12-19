# tests/test_full_session.py
import pytest
import socket
import asyncio
import json
import threading
import struct
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
            # Handle Discovery (D1) or LAN Search (30)
            if cmd == 0xD1 or cmd == 0x30:
                 # Respond Phase 1
                 payload = b'\x00' * 60
                 device_id = b'MOCK_DEVICE_ID_12345'
                 payload = device_id + payload[20:]
                 resp = bytearray([0xF1, 0xDD]) # Response type DD
                 resp.extend(b'\x00\x3C') # Length 60 (Outer payload len)

                 # Note: DiscoveryPhase expects payload starting after Outer Header (4 bytes)
                 # It doesn't strictly parse inner header for discovery response?
                 # modules/discovery.py: self.device_info = response_data[4:56]
                 # So just Outer + Payload. No Inner Header needed for Discovery Response (DD)?
                 # Wait, MockCamera sent 0xF1 0xDD [Len] [Payload]. That is 4 bytes header.
                 # So this matches.

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
                # Login response should be F1 D0 [Len] [Inner] ...
                # Inner must be 4 bytes now.
                # data is the request packet. We can echo it back if it's valid.
                # Request: F1 D0 [Len] [D1 00 Seq] [Artemis]
                # Response should contain success subcommand (0x01 or 0x04) in inner header.

                # Construct proper response
                # Outer
                resp = bytearray([0xF1, 0xD0])

                # Inner: D1 01 00 01 (Type D1, Sub 01=ACK, Seq 1)
                inner = b'\xD1\x01\x00\x01'

                # Payload: empty or some ack data?
                # CameraClient checks 'subcommand' from unwrapped packet.
                # unwrap_pppp parses inner header.

                # Length = 4 (Inner) + 0 (Payload) = 4
                length = 4
                resp.extend(length.to_bytes(2, 'big'))
                resp.extend(inner)

                sock.sendto(resp, addr)

            elif cmd == 0xD3: # Heartbeat / Command
                # Respond
                # Echo inner header?
                # Request: F1 D3 [Len] [Inner] [JSON]
                # Response: F1 D3 [Len] [Inner] [JSON_ACK]

                # Extract Inner Header from request (bytes 4-8)
                if len(data) >= 8:
                    # Construct response
                    resp = bytearray([0xF1, 0xD3])
                    # Payload: same as request for echo?
                    # Or just simple ack.
                    # Let's echo the whole packet for simplicity if client accepts it.
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
