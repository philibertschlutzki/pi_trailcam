# tests/mock_camera_full.py
import socket
import select
import struct
import threading
import time

class MockCamera:
    def __init__(self):
        self.running = True
        self.sock_32108 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_32108.bind(('127.0.0.1', 32108))

        self.sock_40611 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_40611.bind(('127.0.0.1', 40611))

        self.sockets = [self.sock_32108, self.sock_40611]
        print("Mock Camera listening on 32108 and 40611")

    def run(self):
        try:
            while self.running:
                ready, _, _ = select.select(self.sockets, [], [], 1.0)
                for sock in ready:
                    data, addr = sock.recvfrom(1024)
                    self.handle_packet(sock, data, addr)
        except KeyboardInterrupt:
            pass
        finally:
            for s in self.sockets:
                s.close()

    def handle_packet(self, sock, data, addr):
        port = sock.getsockname()[1]
        # print(f"Received on {port} from {addr}: {data.hex()}")

        if len(data) < 2: return

        magic = data[0]
        cmd = data[1]

        if magic != 0xF1:
            return

        if port == 32108:
            # Phase 1: Discovery (D1 or 30)
            # The client now sends 0x30 (LAN Search)
            if cmd == 0xD1 or cmd == 0x30:
                # Respond with DD
                # Mock response: F1 DD [Len] [Payload: Device Info]
                # Payload needs to be at least 52 bytes for client to be happy
                payload = b'\x00' * 60
                # Put a fake device ID at start
                device_id = b'MOCK_DEVICE_ID_12345' # 20 bytes
                payload = device_id + payload[20:]

                resp = bytearray()
                resp.append(0xF1)
                resp.append(0xDD) # Response type
                resp.extend(struct.pack('>H', len(payload)))
                resp.extend(payload)

                sock.sendto(resp, addr)
                # print("Sent Phase 1 Response")

        elif port == 40611:
            # Phase 2: Port Punching (41)
            # Phase 3: P2P Ready (42)
            if cmd == 0x41:
                # Respond with 41
                sock.sendto(data, addr) # Echo back
                # print("Sent Phase 2 Response")
            elif cmd == 0x42:
                # Respond with 42
                sock.sendto(data, addr) # Echo back
                # print("Sent Phase 3 Response")

if __name__ == "__main__":
    mock = MockCamera()
    mock.run()
