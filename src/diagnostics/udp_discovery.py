import socket
import sys
import time
import argparse

# Default Configuration
TARGET_IP = "192.168.43.1"
BROADCAST_IP = "192.168.43.255"
GLOBAL_BROADCAST = "255.255.255.255"
TIMEOUT = 5.0

# Port List to Scan
TARGET_PORTS = [
    40611,  # From log
    32100,  # CS2P2P Standard
    32108,  # Broadcast Discovery Standard
    10000,
    80,
    57743,  # From config.py
]

# Magic Packets
# 1. Log Packet: f1d10006d10000030048 (Magic F1, Cmd D1 (Discovery), Len 6, Sub 1, Seq 3, 0048)
PACKET_LOG = bytes.fromhex("f1d10006d10000030048")

# 2. Standard LAN Search: f1000000 (Minimal) - Maybe incorrect as F1 is PPPP magic
PACKET_MINIMAL = bytes.fromhex("f1d10006d10000010000") # Constructed similar to log packet but simpler

def create_socket(bind_port=0, broadcast=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if broadcast:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Allow reusing address to avoid "Address already in use"
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(('0.0.0.0', bind_port))
        # Set timeout
        sock.settimeout(TIMEOUT)
        return sock
    except Exception as e:
        print(f"[-] Failed to bind to port {bind_port}: {e}")
        return None

def scan_ports():
    print(f"[*] Starting UDP Discovery Scan...")
    print(f"[*] Target IP: {TARGET_IP}")
    print(f"[*] Broadcast IPs: {BROADCAST_IP}, {GLOBAL_BROADCAST}")
    print(f"[*] Timeout: {TIMEOUT}s")

    sock = create_socket(bind_port=0, broadcast=True)
    if not sock:
        return

    listen_sock = create_socket(bind_port=0, broadcast=True) # Socket for listening if we want separate? No, use same.
    # Actually, if we send from one socket, response usually comes back to that socket.

    # We will use one socket for sending and receiving to simplify "source port" logic for now (random source port).
    # But some cameras reply to specific source ports. The user plan says "Bind on 0.0.0.0 (random port)".

    try:
        for port in TARGET_PORTS:
            print(f"\n[+] Scanning Target Port: {port}")

            # Send Unicast
            print(f"    -> Sending Unicast to {TARGET_IP}:{port}")
            sock.sendto(PACKET_LOG, (TARGET_IP, port))
            sock.sendto(PACKET_MINIMAL, (TARGET_IP, port))

            # Send Broadcast
            print(f"    -> Sending Broadcast to {BROADCAST_IP}:{port}")
            sock.sendto(PACKET_LOG, (BROADCAST_IP, port))

            print(f"    -> Sending Global Broadcast to {GLOBAL_BROADCAST}:{port}")
            sock.sendto(PACKET_LOG, (GLOBAL_BROADCAST, port))

        # Listen for responses
        print(f"\n[*] Listening for responses for {TIMEOUT} seconds...")
        start_time = time.time()
        while time.time() - start_time < TIMEOUT:
            try:
                data, addr = sock.recvfrom(2048)
                print(f"\n[!] RECEIVED RESPONSE!")
                print(f"    Source: {addr}")
                print(f"    Data: {data.hex()}")
                return # Stop after first response? Or continue? Let's stop for now as success.
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break

        print("\n[-] No responses received.")

    except KeyboardInterrupt:
        print("\n[*] Scan interrupted.")
    finally:
        sock.close()

if __name__ == "__main__":
    scan_ports()
