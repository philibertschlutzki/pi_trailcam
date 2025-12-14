# tests/mock_camera_simple.py
import socket
import select
import sys

def run_mock():
    # Bind to localhost for testing
    ip = "127.0.0.1"
    port = 32108

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    print(f"Mock Camera listening on {ip}:{port}")

    try:
        while True:
            ready = select.select([sock], [], [], 1.0)
            if ready[0]:
                data, addr = sock.recvfrom(1024)
                print(f"Received from {addr}: {data.hex()}")

                # Logic to simulate camera behavior
                # Expects Big-Endian Length, Inner Header, CMD 0xD1

                # Check Magic
                if data[0] != 0xF1:
                    print("Ignored: Invalid Magic")
                    continue

                # Check CmdType
                cmd_type = data[1]
                if cmd_type == 0x30:
                     print("Ignored: Legacy CmdType 0x30")
                     continue
                if cmd_type != 0xD1:
                     print(f"Ignored: CmdType {hex(cmd_type)}")
                     continue

                # Check Length (Big Endian)
                length_be = (data[2] << 8) | data[3]
                length_le = (data[3] << 8) | data[2]

                actual_payload_len = len(data) - 4

                if length_be == actual_payload_len:
                    print(f"Valid Big-Endian Length: {length_be}")

                    # Check Inner Header existence
                    # If length is small (e.g. 2), likely no inner header if we expect one.
                    # Prompt says Inner Header is required.
                    # Inner header is 4 bytes.
                    if length_be < 4:
                        print("Ignored: Payload too short for Inner Header")
                        continue

                    # Send Response
                    # Response format: F1 [CmdType] [Length] [InnerHeader...]
                    # Usually echoes back with maybe modified Inner Header
                    response = bytearray(data)
                    # Modify something to show it's a response
                    response[1] = 0xDD # Use different CMD type for response maybe, or same.
                    # Prompt A result says: "Response received: f1..."
                    # Discovery response is usually F1 D1 ... or F1 DD ...
                    # Let's verify what the prompt expects. "f1d1..." or similar.
                    # Prompt D says: "Expects Response: Magic F1, CmdType DD or D1"

                    sock.sendto(response, addr)
                    print(f"Sent response to {addr}")

                elif length_le == actual_payload_len:
                    print("Ignored: Little-Endian Length detected (simulating failure)")
                else:
                    print(f"Ignored: Length mismatch (BE={length_be}, LE={length_le}, Actual={actual_payload_len})")

    except KeyboardInterrupt:
        print("\nStopping Mock Camera")
    finally:
        sock.close()

if __name__ == "__main__":
    run_mock()
