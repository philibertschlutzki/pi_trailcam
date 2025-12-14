# tests/test_pppp_format.py
import socket
import struct
import sys
import time
import select

# Default to localhost for testing if no argument provided, or use provided IP
# In real scenario, default is 192.168.43.1
camera_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
camera_port = 32108

print(f"Targeting Camera at {camera_ip}:{camera_port}")

def send_and_wait(sock, data, name):
    print(f"\n--- Test: {name} ---")
    print(f"Sending: {data.hex()}")

    try:
        sock.sendto(data, (camera_ip, camera_port))

        ready = select.select([sock], [], [], 2.0)
        if ready[0]:
            resp, addr = sock.recvfrom(1024)
            print(f"✅ Response received from {addr}: {resp.hex()}")
            return True
        else:
            print("❌ Timeout (2.00s)")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def run_tests():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 0)) # Bind to OS assigned port
    sock.setblocking(0) # Non-blocking for select

    try:
        # PPPP structure:
        # Magic (F1), CmdType (1B), Length (2B), ...

        # Test 1: Big-Endian Length (F1 D1 00 06 ...)
        # Inner Header: CmdType (D1), SubCmd (00), Seq (00 01), Reserved (00) -> 5 bytes?
        # The prompt says: "Inner Header + 2-Byte Payload" = 6 bytes?
        # Wait, Inner Header is usually 4 bytes?
        # Prompt B says: Inner Header: session_type, subcommand, sequence, reserved. That's 4 fields.
        # struct.pack('>BBHB', ...) -> 1+1+2+1 = 5 bytes?
        # Let's check memory: "4-byte Inner Header (Type, Subcommand, Sequence)"
        # Memory says: "4-byte Inner Header (Type, Subcommand, Sequence)".
        # Wait, 1+1+2 = 4 bytes.
        # Prompt B says: "InnerHeader Dataclass with: session_type, subcommand, sequence, reserved". That would be 1+1+2+1 = 5 bytes if reserved is 1 byte.
        # Let's check "PROTOCOL_ANALYSIS.md" if it existed, but I rely on memory.
        # Memory says: "4-byte Inner Header (Type, Subcommand, Sequence)". It might omit reserved.
        # Or maybe Sequence is 1 byte? No, Sequence is Big Endian 16-bit integer (2 bytes).
        # So Type(1) + Sub(1) + Seq(2) = 4 bytes.

        # Prompt A says: "F1 D1 00 06 ... d1 00 00 01 ..."
        # 00 06 is length.
        # d1 00 00 01 -> 4 bytes.
        # So Inner Header is 4 bytes.
        # Plus 2 bytes payload? "00 48"
        # Total 6 bytes payload for Outer Header.

        # Test 1: Big-Endian Length, With Inner Header
        # Outer: F1 (Magic), D1 (Cmd), 00 06 (Length BE)
        # Inner: D1 (Type), 00 (Sub), 00 01 (Seq)
        # Payload: 00 48 (Artemis Seq?)
        packet_be = bytes.fromhex("f1d10006d10000010048")
        if send_and_wait(sock, packet_be, "Big-Endian Length (F1 D1 00 06 ...)"):
             print("-> Big-Endian ist korrekt!")

        # Test 2: Little-Endian Length (F1 D1 06 00 ...)
        packet_le = bytes.fromhex("f1d10600d10000010048")
        send_and_wait(sock, packet_le, "Little-Endian Length (F1 D1 06 00 ...)")

        # Test 3: Outer-only (No Inner Header)
        # Length 2 bytes (00 02)
        packet_outer_only = bytes.fromhex("f1d100020048")
        send_and_wait(sock, packet_outer_only, "Outer-only (No Inner Header)")

        # Test 4: CmdType F1 30 (iLnk legacy)
        packet_ilnk = bytes.fromhex("f1300006d10000010048")
        send_and_wait(sock, packet_ilnk, "CmdType F1 30 (iLnk)")

    finally:
        sock.close()

if __name__ == "__main__":
    run_tests()
