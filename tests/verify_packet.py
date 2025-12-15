import sys
import os
import base64
import struct

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.packet_builder import ArtemisPacketBuilder

def test_packet_structure():
    print("Testing ArtemisPacketBuilder...")

    token = "85087127"
    sequence = 5

    try:
        packet = ArtemisPacketBuilder.build_login_packet(token, sequence)
    except Exception as e:
        print(f"FAILED: Exception during build: {e}")
        return False

    print(f"Packet Length: {len(packet)} (Expected: 53)")
    print(f"Packet Hex: {packet.hex()}")

    # 1. Size Check
    if len(packet) != 53:
        print("FAILED: Packet size is not 53 bytes")
        return False

    # 2. Header Check (F1 D0 00 31)
    if packet[0:4] != b'\xf1\xd0\x00\x31':
        print(f"FAILED: Header mismatch. Got {packet[0:4].hex()}")
        return False

    # 3. Subcommand Check (Byte 20 should be 0x04)
    # 0-3 Header, 4-7 Wrapper, 8-15 Proto, 16-19 Cmd, 20 Subcmd
    subcmd = packet[20]
    if subcmd != 0x04:
        print(f"FAILED: Subcommand is 0x{subcmd:02X} (Expected 0x04)")
        return False

    # 4. Token Check
    # Token "85087127" -> Base64 "ODUwODcxMjc="
    # Should be at offset 28
    # 28-39 should match Base64
    # 40-52 should be nulls

    expected_b64 = base64.b64encode(token.encode('utf-8'))
    print(f"Expected Base64: {expected_b64}")

    token_part = packet[28:53]
    print(f"Token Part Hex: {token_part.hex()}")
    print(f"Token Part Ascii: {token_part}")

    if not token_part.startswith(expected_b64):
        print("FAILED: Token part does not start with expected Base64")
        return False

    # Check padding
    padding_len = 25 - len(expected_b64)
    expected_padding = b'\x00' * padding_len
    if token_part[len(expected_b64):] != expected_padding:
        print("FAILED: Token padding is incorrect")
        return False

    print("SUCCESS: Packet structure verification passed!")
    return True

if __name__ == "__main__":
    if test_packet_structure():
        sys.exit(0)
    else:
        sys.exit(1)
