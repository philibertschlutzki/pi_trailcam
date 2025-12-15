import sys
import os
import struct
import logging

# Add project root to path
sys.path.append(os.getcwd())

from modules.packet_builder import ArtemisPacketBuilder

logging.basicConfig(level=logging.DEBUG)

def hex_dump(data):
    return " ".join(f"{b:02X}" for b in data)

def test_login_packet_construction():
    print("=== Testing Login Packet Construction ===")

    # Test values from user context
    token = "ABCDEF1234567890ABCDEF1234567890" # 32 chars
    ble_sequence_int = 72 # 0x48
    ble_sequence_bytes = struct.pack('<I', ble_sequence_int) # 48 00 00 00
    sequence = 1

    print(f"Token: {token}")
    print(f"BLE Sequence (int): {ble_sequence_int}")
    print(f"BLE Sequence (bytes): {hex_dump(ble_sequence_bytes)}")
    print(f"Sequence: {sequence}")

    try:
        packet = ArtemisPacketBuilder.build_login_packet(
            token,
            sequence,
            ble_seq=ble_sequence_bytes
        )

        print("\nGenerated Packet:")
        print(hex_dump(packet))

        print("\nAnalysis:")

        # 1. Outer Header
        outer_magic = packet[0]
        outer_type = packet[1]
        # Expecting Little Endian Length now
        outer_len = struct.unpack('<H', packet[2:4])[0]
        print(f"Outer Magic: {outer_magic:02X} (Expected F1)")
        print(f"Outer Type:  {outer_type:02X} (Expected D0)")
        print(f"Outer Len:   {outer_len} (0x{outer_len:04X})")
        print(f"Outer Len Bytes: {hex_dump(packet[2:4])}")

        # 2. Inner Header
        inner_type = packet[4]
        inner_sub = packet[5]
        print(f"Inner Type: {inner_type:02X} (Expected D1)")
        print(f"Inner Sub:  {inner_sub:02X} (Expected 03)")

        # Expecting 4 bytes LE
        inner_seq_bytes = packet[6:10]
        inner_seq = struct.unpack('<I', inner_seq_bytes)[0]
        print(f"Inner Seq Bytes: {hex_dump(inner_seq_bytes)}")
        print(f"Inner Seq Val:   {inner_seq}")

        # 3. Payload
        payload_start = 10 # 4 Outer + 6 Inner

        magic = packet[payload_start:payload_start+8]
        print(f"Artemis Magic: {hex_dump(magic)} (Expected 41 52 54 45 4D 49 53 00)")

        version_offset = payload_start + 8

        # Version (4 bytes)
        version_bytes = packet[version_offset:version_offset+4]
        print(f"Version: {hex_dump(version_bytes)} (Expected 02 00 00 00)")

        # BLE Seq (4 bytes)
        ble_seq_offset = version_offset + 4
        ble_seq_bytes_packet = packet[ble_seq_offset:ble_seq_offset+4]
        print(f"BLE Seq Field: {hex_dump(ble_seq_bytes_packet)} (Expected 48 00 00 00)")

        # Token Len (4 bytes)
        token_len_offset = ble_seq_offset + 4
        token_len_bytes = packet[token_len_offset:token_len_offset+4]
        token_len_val = struct.unpack('<I', token_len_bytes)[0]
        print(f"Token Len Field: {hex_dump(token_len_bytes)} (Val: {token_len_val})")

        # Token Data
        token_data_offset = token_len_offset + 4
        token_data = packet[token_data_offset:]
        print(f"Token Data: {hex_dump(token_data)}")
        print(f"Token String: {token_data.decode('utf-8', errors='replace')}")

        assert len(token_data) == 32
        assert token_len_val == 32

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_login_packet_construction()
