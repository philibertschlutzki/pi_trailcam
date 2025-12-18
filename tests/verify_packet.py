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

    print(f"Packet Length: {len(packet)}")
    print(f"Packet Hex: {packet.hex()}")

    # 1. Header Check (F1 D0 [Length BE])
    if packet[0] != 0xF1 or packet[1] != 0xD0:
        print(f"FAILED: Header mismatch. Got {packet[0:2].hex()}")
        return False

    length_be = struct.unpack('>H', packet[2:4])[0]
    expected_len = len(packet) - 4
    if length_be != expected_len:
        print(f"FAILED: Length mismatch. Header says {length_be}, actual payload is {expected_len}")
        return False

    # 2. Inner Header Check (D1 03 [Seq BE])
    # Should be 4 bytes
    inner = packet[4:8]
    if inner[0] != 0xD1 or inner[1] != 0x03:
         print(f"FAILED: Inner Header mismatch. Got {inner[0:2].hex()}")
         return False

    seq_be = struct.unpack('>H', inner[2:4])[0]
    if seq_be != sequence:
        print(f"FAILED: Sequence mismatch. Got {seq_be}, expected {sequence}")
        return False

    # 3. Payload Check
    # "ARTEMIS\x00"
    if packet[8:16] != b'ARTEMIS\x00':
        print("FAILED: Protocol ID mismatch")
        return False

    # 4. Token Check
    # Layer 4 (12 bytes) + Token
    # Layer 4 starts at offset 16
    # Token starts at offset 28
    token_payload = packet[28:]
    if token_payload.decode('utf-8') != token:
        print(f"FAILED: Token mismatch. Got {token_payload}")
        return False

    print("SUCCESS: Packet structure verification passed!")
    return True

if __name__ == "__main__":
    if test_packet_structure():
        sys.exit(0)
    else:
        sys.exit(1)
