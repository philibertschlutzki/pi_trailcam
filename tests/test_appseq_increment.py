#!/usr/bin/env python3
"""Test to verify AppSeq increments correctly and doesn't have the 65537 bug."""

import struct
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from get_thumbnail_perp import build_artemis_frame, ARTEMIS_MSG_REQUEST


def test_appseq_increment():
    """Verify that AppSeq values are encoded correctly in little-endian."""
    
    print("Testing AppSeq encoding in ARTEMIS frames...")
    
    test_cases = [
        (1, b'\x01\x00\x00\x00'),   # AppSeq=1 should be 01 00 00 00
        (2, b'\x02\x00\x00\x00'),   # AppSeq=2 should be 02 00 00 00
        (3, b'\x03\x00\x00\x00'),   # AppSeq=3 should be 03 00 00 00
        (65537, b'\x01\x00\x01\x00'),  # AppSeq=65537 (the bug value) should be 01 00 01 00
    ]
    
    for app_seq, expected_bytes in test_cases:
        frame = build_artemis_frame(ARTEMIS_MSG_REQUEST, app_seq, b"test")
        
        # Extract AppSeq bytes from frame
        # Frame structure: ARTEMIS\x00 (8) + MsgType (4) + AppSeq (4) + PayloadLen (4) + Payload
        appseq_offset = 8 + 4  # Skip ARTEMIS\x00 and MsgType
        actual_bytes = frame[appseq_offset:appseq_offset + 4]
        
        print(f"  AppSeq={app_seq:6d}: expected={expected_bytes.hex()}, actual={actual_bytes.hex()}", end="")
        
        if actual_bytes == expected_bytes:
            print(" ✅")
        else:
            print(f" ❌ MISMATCH!")
            return False
    
    print("\n✅ All AppSeq encodings correct!")
    return True


def test_heartbeat_appseq_sequence():
    """Simulate the heartbeat sequence to verify no AppSeq=65537 bug."""
    
    print("\nTesting heartbeat AppSeq sequence (simulating Session class)...")
    
    class MockSession:
        def __init__(self):
            self.app_seq = 0
        
        def send_login(self):
            self.app_seq += 1
            return self.app_seq
        
        def send_heartbeat(self):
            self.app_seq += 1
            heartbeat_b64_payload = b"MzlB36X/IVo8ZzI5rG9j1w==\x00"
            frame = build_artemis_frame(ARTEMIS_MSG_REQUEST, self.app_seq, heartbeat_b64_payload)
            return self.app_seq, frame
    
    session = MockSession()
    
    # Simulate login
    login_seq = session.send_login()
    print(f"  Login AppSeq: {login_seq}")
    assert login_seq == 1, f"Login should have AppSeq=1, got {login_seq}"
    
    # Simulate heartbeats
    expected_heartbeat_seqs = [2, 3, 4, 5, 6]
    for i, expected_seq in enumerate(expected_heartbeat_seqs):
        hb_seq, frame = session.send_heartbeat()
        
        # Extract AppSeq from frame
        appseq_offset = 8 + 4
        appseq_bytes = frame[appseq_offset:appseq_offset + 4]
        appseq_value = struct.unpack('<I', appseq_bytes)[0]
        
        print(f"  Heartbeat {i+1}: AppSeq={hb_seq} (frame bytes: {appseq_bytes.hex()}, decoded: {appseq_value})", end="")
        
        if hb_seq == expected_seq and appseq_value == expected_seq:
            print(" ✅")
        else:
            print(f" ❌ Expected {expected_seq}")
            return False
        
        # Check for the bug value
        if appseq_value == 65537:
            print(f"  ❌ BUG DETECTED: AppSeq jumped to 65537!")
            return False
    
    print("\n✅ Heartbeat sequence correct, no 65537 bug!")
    return True


if __name__ == "__main__":
    success = True
    
    try:
        if not test_appseq_increment():
            success = False
        
        if not test_heartbeat_appseq_sequence():
            success = False
        
        if success:
            print("\n🎉 All tests passed!")
            sys.exit(0)
        else:
            print("\n❌ Some tests failed")
            sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
