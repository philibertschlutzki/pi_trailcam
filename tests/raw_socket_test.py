#!/usr/bin/env python3
import socket
import time
import struct
import sys

# Configuration
TARGET_IP = '127.0.0.1' # Change to 192.168.43.1 for real camera
TARGET_PORT = 40611

def run_test():
    print(f"Starting Raw Socket Test targeting {TARGET_IP}:{TARGET_PORT}")

    # Create raw UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 0))
    local_port = sock.getsockname()[1]
    print(f"Listening on port {local_port}")

    # Send discovery packet
    # F1 D1 00 06 D1 00 00 01 + Artemis Seq
    packet = bytes.fromhex('F1D10006D1000001' + '001B')

    print(f"Sent discovery packet to {TARGET_IP}:{TARGET_PORT}")
    sock.sendto(packet, (TARGET_IP, TARGET_PORT))

    # Try to receive
    sock.settimeout(10)
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            print(f"✓ Received {len(data)} bytes from {addr}: {data.hex()}")
            if data[0] == 0xF1:
                 print("  -> Valid Magic Byte 0xF1")
                 if len(data) > 5 and data[5] == 0x01:
                     print("  -> Valid Subcommand 0x01 (Discovery ACK)")
                     break
    except socket.timeout:
        print("✗ No response after 10 seconds")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        TARGET_IP = sys.argv[1]
    run_test()
