# tests/test_stress.py
import pytest
import asyncio
import socket
import json
import time
import threading
from modules.protocol.pppp import PPPPProtocol
from modules.command_engine import CommandEngine
from modules.heartbeat import HeartbeatManager
from tests.test_command_engine import MockCameraCommand

@pytest.fixture
def mock_stress_camera():
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
    # Ensure sockets are closed by MockCamera's finally block,
    # but we need to trigger it by stopping run loop.
    # We might need to send a dummy packet or wait?
    # Actually MockCamera closes sockets in finally block.
    # But run() is in thread.
    time.sleep(0.1) # Give time for thread to close

@pytest.mark.asyncio
async def test_100_sequential_commands(mock_stress_camera):
    camera_ip = "127.0.0.1"
    pppp = PPPPProtocol()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 0))
    sock.setblocking(False)

    engine = CommandEngine(camera_ip, pppp, sock)

    start_time = time.time()
    for i in range(100):
        resp = await engine.send_command(1000+i, {"seq": i}, timeout_sec=0.5)
        assert resp["cmdId"] == 1000+i
        assert resp["seq"] == i

    duration = time.time() - start_time
    print(f"100 commands took {duration:.2f}s")
    assert duration < 10.0 # Should be fast locally

@pytest.mark.asyncio
async def test_heartbeat_jitter(mock_stress_camera):
    camera_ip = "127.0.0.1"
    pppp = PPPPProtocol()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 0))

    # We want to measure the interval of packets SENT by HeartbeatManager
    # We can use a spy socket or just modify Mock to record arrival times?
    # Let's modify HeartbeatManager to expose last_send_time history?
    # Or just subclass it.

    class InstrumentedHeartbeat(HeartbeatManager):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.send_times = []

        async def start(self, interval_sec: float = 3.0):
            # Wrap socket.sendto to record time?
            # Or just check self.last_heartbeat_time updates
            # But start loop runs internally.
            # We can override sendto on the socket object?

            # Better: Monitor the Mock side arrival times.
            return await super().start(interval_sec)

    # Monitor arrival on Mock
    arrival_times = []

    original_handle = mock_stress_camera.handle_packet
    def tracking_handle(sock, data, addr):
        if len(data) > 1 and data[1] == 0xD3: # Heartbeat
             arrival_times.append(time.time())
        original_handle(sock, data, addr)

    mock_stress_camera.handle_packet = tracking_handle

    hb = HeartbeatManager(camera_ip, pppp, sock)
    task = asyncio.create_task(hb.start(interval_sec=0.1)) # Fast interval for test

    await asyncio.sleep(1.0) # wait for ~10 heartbeats

    await hb.stop()
    task.cancel()
    try:
        await task
    except:
        pass

    # Analyze jitter
    assert len(arrival_times) >= 8
    intervals = [t2 - t1 for t1, t2 in zip(arrival_times, arrival_times[1:])]
    avg_interval = sum(intervals) / len(intervals)
    print(f"Average interval: {avg_interval:.4f}s")

    # Check if close to 0.1
    assert 0.08 < avg_interval < 0.15
