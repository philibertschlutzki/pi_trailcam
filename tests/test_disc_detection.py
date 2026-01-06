#!/usr/bin/env python3
"""Test DISC packet detection in send_prelogin method.

This test validates that the _is_disc_packet() helper correctly identifies
disconnect signals (F1 0x41 and F1 0xF0) during the Pre-Login phase.
"""

import sys
import os

# Add parent directory to path to import get_thumbnail_perp
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from get_thumbnail_perp import Session


def test_is_disc_packet():
    """Test that _is_disc_packet correctly identifies DISC packets."""
    
    # Test 0x41 DISC packet (F1 41 ...)
    disc_41 = bytes.fromhex("f1410008d1000000")
    assert Session._is_disc_packet(disc_41), "Should detect F1 41 as DISC"
    
    # Test 0xF0 DISC packet (F1 F0 ...)
    disc_f0 = bytes.fromhex("f1f00008d1000000")
    assert Session._is_disc_packet(disc_f0), "Should detect F1 F0 as DISC"
    
    # Test non-DISC packets
    # DATA packet (F1 D0)
    data_pkt = bytes.fromhex("f1d00007d100000041434b")
    assert not Session._is_disc_packet(data_pkt), "Should not detect F1 D0 as DISC"
    
    # ACK packet (F1 D1)
    ack_pkt = bytes.fromhex("f1d10006d10000000000")
    assert not Session._is_disc_packet(ack_pkt), "Should not detect F1 D1 as DISC"
    
    # PRE packet (F1 F9)
    pre_pkt = bytes.fromhex("f1f90020d1000000")
    assert not Session._is_disc_packet(pre_pkt), "Should not detect F1 F9 as DISC"
    
    # FRAG packet (F1 42)
    frag_pkt = bytes.fromhex("f14200144c42435300000000")
    assert not Session._is_disc_packet(frag_pkt), "Should not detect F1 42 as DISC"
    
    # Edge cases
    # Too short (only 1 byte)
    short_pkt = bytes.fromhex("f1")
    assert not Session._is_disc_packet(short_pkt), "Should handle short packets"
    
    # Empty packet
    empty_pkt = b""
    assert not Session._is_disc_packet(empty_pkt), "Should handle empty packets"
    
    # Wrong magic byte (not F1)
    wrong_magic = bytes.fromhex("f0410008d1000000")
    assert not Session._is_disc_packet(wrong_magic), "Should require F1 magic byte"
    
    print("✅ All _is_disc_packet tests passed!")


def test_is_simple_ack_payload():
    """Test that _is_simple_ack_payload correctly identifies ACK packets."""
    
    # Valid ACK packet: F1 D0 00 07 D1 00 00 00 "ACK"
    ack_pkt = bytes.fromhex("f1d00007d100000041434b")
    assert Session._is_simple_ack_payload(ack_pkt), "Should detect valid ACK"
    
    # ACK packet with extra data
    ack_long = bytes.fromhex("f1d00007d100000041434b00000000")
    assert Session._is_simple_ack_payload(ack_long), "Should detect ACK with trailing bytes"
    
    # Not an ACK - DATA packet without "ACK" payload
    data_pkt = bytes.fromhex("f1d00007d100000042414400")
    assert not Session._is_simple_ack_payload(data_pkt), "Should not detect non-ACK data"
    
    # DISC packet should not be ACK
    disc_pkt = bytes.fromhex("f1410008d100000041434b")
    assert not Session._is_simple_ack_payload(disc_pkt), "DISC should not be detected as ACK"
    
    print("✅ All _is_simple_ack_payload tests passed!")


def test_accept_ack_or_disc_predicate():
    """Test the predicate logic used in send_prelogin."""
    
    # Simulate the predicate function used in send_prelogin
    def accept_ack_or_disc(pkt: bytes) -> bool:
        """Accept both ACK and DISC packets to avoid timeout."""
        return Session._is_simple_ack_payload(pkt) or Session._is_disc_packet(pkt)
    
    # Should accept ACK
    ack_pkt = bytes.fromhex("f1d00007d100000041434b")
    assert accept_ack_or_disc(ack_pkt), "Should accept ACK packet"
    
    # Should accept DISC (0x41)
    disc_41 = bytes.fromhex("f1410008d1000000")
    assert accept_ack_or_disc(disc_41), "Should accept DISC 0x41 packet"
    
    # Should accept DISC (0xF0)
    disc_f0 = bytes.fromhex("f1f00008d1000000")
    assert accept_ack_or_disc(disc_f0), "Should accept DISC 0xF0 packet"
    
    # Should reject other packets
    data_pkt = bytes.fromhex("f1d00007d100000042414400")
    assert not accept_ack_or_disc(data_pkt), "Should reject non-ACK DATA packet"
    
    frag_pkt = bytes.fromhex("f14200144c42435300000000")
    assert not accept_ack_or_disc(frag_pkt), "Should reject FRAG packet"
    
    print("✅ All predicate logic tests passed!")


def test_packet_type_priorities():
    """Test that we correctly differentiate between ACK and DISC in response handling."""
    
    # ACK packet
    ack_pkt = bytes.fromhex("f1d00007d100000041434b")
    assert Session._is_simple_ack_payload(ack_pkt), "Should be ACK"
    assert not Session._is_disc_packet(ack_pkt), "Should not be DISC"
    
    # DISC packet (0x41)
    disc_41 = bytes.fromhex("f1410008d1000000")
    assert Session._is_disc_packet(disc_41), "Should be DISC"
    assert not Session._is_simple_ack_payload(disc_41), "Should not be ACK"
    
    # DISC packet (0xF0)
    disc_f0 = bytes.fromhex("f1f00008d1000000")
    assert Session._is_disc_packet(disc_f0), "Should be DISC"
    assert not Session._is_simple_ack_payload(disc_f0), "Should not be ACK"
    
    print("✅ All packet type priority tests passed!")


if __name__ == "__main__":
    test_is_disc_packet()
    test_is_simple_ack_payload()
    test_accept_ack_or_disc_predicate()
    test_packet_type_priorities()
    print("\n✅ All tests passed successfully!")

