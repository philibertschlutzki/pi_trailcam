# tests/test_pppp_wrapper.py
import pytest
import struct
from modules.protocol.pppp import PPPPProtocol, PPPPOuterHeader, PPPPInnerHeader
from modules.protocol.constants import PPPPConstants

@pytest.fixture
def protocol():
    return PPPPProtocol()

def test_pppp_constants():
    assert PPPPConstants.MAGIC_STANDARD == 0xF1
    assert PPPPConstants.CMD_DISCOVERY == 0xD1
    assert PPPPConstants.CMD_LOGIN == 0xD0

def test_outer_header_serialization():
    # OuterHeader(0xF1, 0xD1, 6) -> bytes
    header = PPPPOuterHeader(0xF1, 0xD1, 6)
    data = header.to_bytes()
    assert data == b'\xf1\xd1\x00\x06'

def test_inner_header_serialization():
    # InnerHeader(0xD1, 0x00, 1) -> bytes (4 bytes)
    header = PPPPInnerHeader(0xD1, 0x00, 1)
    data = header.to_bytes()
    assert data == b'\xd1\x00\x00\x01'

def test_wrap_discovery_packet(protocol):
    # wrap_discovery(0x0048)
    # Payload: 00 48 (2 bytes)
    # Inner: D1 00 00 01 (4 bytes)
    # Outer Length: 4 + 2 = 6 bytes
    packet = protocol.wrap_discovery(0x0048)

    assert packet.startswith(b'\xf1\xd1\x00\x06') # Outer (Length 6)
    assert packet[4:8] == b'\xd1\x00\x00\x01' # Inner (4 bytes)
    assert packet[8:] == b'\x00\x48' # Payload
    assert protocol.pppp_sequence == 2

def test_wrap_init_packet(protocol):
    packet = protocol.wrap_init()
    # Updated: Init packet (0xE1) has 0 length and no payload
    # Outer Header: F1 E1 00 00
    assert packet == b'\xf1\xe1\x00\x00'
    # Sequence should NOT increment for init
    assert protocol.pppp_sequence == 1

def test_wrap_login_packet(protocol):
    payload = b'ARTEMIS_PAYLOAD'
    packet = protocol.wrap_login(payload)

    # Outer: F1 D0 ...
    assert packet[0] == 0xF1
    assert packet[1] == 0xD0

    # Check length
    # Inner (4) + Payload (15) = 19
    length = struct.unpack('>H', packet[2:4])[0]
    assert length == 4 + len(payload)

    assert protocol.pppp_sequence == 2

def test_wrap_heartbeat_packet(protocol):
    payload = b'{"cmdId": 525}'
    packet = protocol.wrap_heartbeat(payload)

    # Outer: F1 D3 ...
    assert packet[1] == 0xD3
    assert protocol.pppp_sequence == 2

def test_sequence_increment(protocol):
    protocol.wrap_discovery(0) # 1 -> 2
    protocol.wrap_discovery(0) # 2 -> 3
    protocol.wrap_discovery(0) # 3 -> 4
    assert protocol.pppp_sequence == 4

def test_sequence_wraparound(protocol):
    protocol.pppp_sequence = 0xFFFF
    protocol.wrap_discovery(0) # FFFF -> 1
    assert protocol.pppp_sequence == 1

def test_error_handling(protocol):
    large_payload = b'x' * 5000
    with pytest.raises(ValueError):
        protocol.wrap_login(large_payload)
