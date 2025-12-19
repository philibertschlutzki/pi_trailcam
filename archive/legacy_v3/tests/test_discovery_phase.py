# tests/test_discovery_phase.py
import pytest
import asyncio
import socket
from modules.discovery import DiscoveryPhase
from modules.protocol.pppp import PPPPProtocol
from tests.mock_camera_full import MockCamera
import threading

# Fixture to start mock camera in background
@pytest.fixture
def mock_camera():
    mock = MockCamera()
    thread = threading.Thread(target=mock.run, daemon=True)
    thread.start()
    yield mock
    mock.running = False
    # Sending dummy packet to unblock select if needed, or rely on timeout
    # But daemon thread will be killed anyway.

@pytest.mark.asyncio
async def test_discovery_phase_success(mock_camera):
    # Setup
    pppp = PPPPProtocol()
    # Mock camera listens on 127.0.0.1
    discovery = DiscoveryPhase("127.0.0.1", 0x0048, pppp)

    result = await discovery.execute()

    assert result["success"] == True
    assert result["device_id"] is not None
    # Mock returns MOCK_DEVICE_ID... (20 bytes)
    assert result["device_id"] == b'MOCK_DEVICE_ID_12345'

@pytest.mark.asyncio
async def test_discovery_phase_timeout():
    # No mock camera running (port 32108 closed/unreachable)
    pppp = PPPPProtocol()
    discovery = DiscoveryPhase("127.0.0.1", 0x0048, pppp)

    # Override ports in discovery if possible?
    # Or just use an IP that doesn't respond.
    # 127.0.0.1 will reject if no listener (ICMP Unreachable) or timeout if firewall drop.
    # If using non-listening port, recvfrom raises ConnectionRefusedError usually on localhost.

    # Let's target a port that MockCamera is NOT listening on
    # But DiscoveryPhase hardcodes 32108.
    # So we need to ensure Mock is NOT running for this test.
    # Pytest runs sequentially.

    # We can try to bind to 32108 ourselves to block it but not answer?
    # Or just run against an unused IP?
    discovery.camera_ip = "192.0.2.1" # TEST-NET-1 (non-routable/reserved for docs)
    # This might take 5s timeout.

    # Use shorter timeout for test
    # Monkeypatching asyncio.wait_for? Or modifying class.

    # Just run it, 5s is fine.

    result = await discovery.execute()
    assert result["success"] == False
    assert "Phase 1 failed" in result["error"]
