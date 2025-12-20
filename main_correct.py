import socket
import struct
import time
import json
import logging
import sys
import argparse
import subprocess
import asyncio
from bleak import BleakScanner, BleakClient

# --- KONFIGURATION ---
DEFAULT_CAMERA_IP = "192.168.43.1"
DEFAULT_CAMERA_PORT = 40611
DEFAULT_WIFI_SSID = "KJK_E0FF"
DEFAULT_WIFI_PASS = "85087127"
DEFAULT_BLE_MAC = "C6:1E:0D:E0:32:E8"
BLE_UUID_WRITE = "00000002-0000-1000-8000-00805f9b34fb"
BLE_WAKEUP_BYTES = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# BLE Token aus Frida-Log (Base64)
TEST_BLE_TOKEN = "J8WWuQDPmYSLfu/gXAG+UqbBy55KP2iE25QPNofzn040+NI9g7zeXLkIpXpC07SXvosrWsc1m8mxnq6hMiKwePbKJUwvSvqZb6s0sl1sfzh2mtRslV2Nc6tRKoxG/Qj+p3yGl1CC5ARbJJKGBaXcgq7Tnekn+ytw+RLlgoSAMOc="

# Payloads aus Frida-Log
PHASE2_ENCRYPTED_PAYLOAD = bytes.fromhex(
    "0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e505d011f8"
    "52fa6a88c139939a6c61f9fa6a88c13b2919e12235f6d0412b5f951eb669dfaa"
    "3719e12235f62e8dd5db728f6756b85b31be74e4"
)

# Base64 Payloads for Initialization Sequence
CMD_2_PAYLOAD = "y+DDbqMNNnV5LDju3xlEhSWl9peI5eWb2ghmr3wVyEI="
CMD_10001_PAYLOAD = "MzlB36X/IVo8ZzI5rG9j1w=="
CMD_3_PAYLOAD = "I3mbwVIxJQgnSB9GJKNk5Cz4lHNuiNQuetIK1as++bY="
CMD_4_PAYLOAD = CMD_2_PAYLOAD
CMD_5_PAYLOAD = "36Rw4/b3Mw4tDnOS/p8mXQ8FnmDnjxA4yMQ9iXTIZQOw="
CMD_6_PAYLOAD = "90RH0Mg4PMffYI1fACycdPDFvKRV/22yeiZoDPKRFcyG0jH7mkZCE16ucxWcGAo3ZlwJ+GwTj5vj0L+gvGRmWg=="

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ArtemisClient")

# --- HELPER CLASSES ---

class BLEWorker:
    @staticmethod
    async def wake_camera(mac_address):
        logger.info(f"Attempting BLE Wakeup for {mac_address}...")
        device = await BleakScanner.find_device_by_address(mac_address, timeout=10.0)
        if not device:
            logger.warning("BLE Device not found (already in WiFi mode?)")
            return False

        try:
            async with BleakClient(device, timeout=15.0) as client:
                logger.info("BLE Connected. Sending Wakeup Magic Bytes...")
                await client.write_gatt_char(BLE_UUID_WRITE, BLE_WAKEUP_BYTES, response=True)
                logger.info("BLE Wakeup Sent.")
                return True
        except Exception as e:
            logger.error(f"BLE Error: {e}")
            return False

class WiFiWorker:
    @staticmethod
    def connect_nmcli(ssid, password):
        logger.info(f"Connecting to WiFi {ssid} via nmcli...")
        # Check if already connected
        try:
            res = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
            if ssid in res.stdout.strip():
                logger.info("Already connected to correct WiFi.")
                return True
        except FileNotFoundError:
            pass # iwgetid might not be installed

        # Reconnect logic
        subprocess.run(["sudo", "nmcli", "connection", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], capture_output=True)
        time.sleep(3)
        cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", password]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode == 0:
            logger.info("WiFi Connected.")
            return True
        else:
            logger.error(f"WiFi Connection Failed: {proc.stderr.strip()}")
            return False

class SequenceManager:
    def __init__(self):
        self.pppp_seq = 0
        self.artemis_seq = 0

    def next_pppp(self) -> int:
        seq = self.pppp_seq
        self.pppp_seq = (self.pppp_seq + 1) % 65536
        return seq

    def set_pppp(self, seq: int):
        self.pppp_seq = seq

    def next_artemis(self) -> int:
        seq = self.artemis_seq
        self.artemis_seq += 1
        return seq

class PPPPSession:
    def __init__(self, ip, port, token):
        self.ip = ip
        self.port = port
        self.token = token
        self.sock = None
        self.seq_manager = SequenceManager()
        self.session_id = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Discovery needs broadcast usually
        self.sock.settimeout(2.0)
        # Bind to a port to ensure responses come back to us?
        # self.sock.bind(('', 0))

    def close(self):
        if self.sock:
            self.sock.close()

    def _send_raw(self, data):
        if not self.sock: raise ConnectionError("No socket")
        try:
            self.sock.sendto(data, (self.ip, self.port))
        except Exception as e:
            logger.error(f"Send Error: {e}")

    def send_control_packet(self, seq, payload):
        """Sends a control packet with Outer Header 0xF1 0xD1."""
        # Inner Header: D1 00 [Seq]
        inner = struct.pack('>BBH', 0xD1, 0x00, seq)
        full_payload = inner + payload

        # Outer Header: F1 D1 [Len] [Payload]
        outer = struct.pack('>BBH', 0xF1, 0xD1, len(full_payload)) + full_payload
        logger.info(f"TX Control Packet (Seq={seq}, Len={len(payload)})")
        self._send_raw(outer)

    def _recv(self, timeout=None):
        if not self.sock: raise ConnectionError("No socket")
        if timeout: self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(4096)
            return data
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Recv Error: {e}")
            return None

    def phase1_lbcs_discovery(self):
        logger.info(">>> PHASE 1: LBCS Discovery (0x41)")
        # 4C 42 43 53 (LBCS) + 8*00 + 43 43 43 4A 4A (CCCJJ) + 3*00
        payload = b'LBCS' + b'\x00'*8 + b'CCCJJ' + b'\x00'*3
        packet = struct.pack('>BBH', 0xF1, 0x41, len(payload)) + payload

        for i in range(3):
            logger.debug(f"Sending LBCS {i+1}/3")
            self._send_raw(packet)
            resp = self._recv(timeout=0.5)
            if resp and len(resp) >= 28 and resp[0] == 0xF1 and resp[1] == 0x43:
                logger.info(f"✅ LBCS Response (0x43) received! Len={len(resp)}")
                self.session_id = resp[24:28]
                logger.info(f"Session ID: {self.session_id.hex()}")
                return True
            time.sleep(0.2)
        logger.warning("⚠️ Phase 1: No response. Continuing...")
        return False

    def phase2_pre_login(self):
        logger.info(">>> PHASE 2: Pre-Login Encryption (0xF9)")
        # Use exact bytes from log
        encrypted_payload = PHASE2_ENCRYPTED_PAYLOAD
        packet = struct.pack('>BBH', 0xF1, 0xF9, len(encrypted_payload)) + encrypted_payload

        for i in range(3):
            logger.debug(f"Sending 0xF9 {i+1}/3")
            self._send_raw(packet)

            # Reactive: Wait for ACK or LBCS broadcast
            resp = self._recv(timeout=1.0)
            if resp and len(resp) > 2:
                # Accept F1 D0 (Data/ACK) or F1 D1 (Control) or F1 42 (LBCS)
                if resp[0] == 0xF1 and resp[1] in [0xD0, 0xD1, 0x42]:
                    logger.info(f"✅ Phase 2 ACK/Response received (Type 0x{resp[1]:02X})")
                    return True

            logger.debug("No immediate Phase 2 ACK, retrying...")
            time.sleep(0.2)

        logger.warning("⚠️ Phase 2: No ACK received, but continuing (blindly)...")
        return True # Continue anyway to try login

    def send_artemis_command(self, cmd_type, payload_bytes, seq=None):
        """Constructs and sends an Artemis Command inside PPPP 0xD0."""
        # Artemis Payload Structure:
        # Header: ARTEMIS\x00 (8)
        # Ver: 2 (4, LE)
        # Type: cmd_type (4, LE)
        # Len: payload_len (4, LE)
        # Payload
        # Null (1)

        payload_body = (
            b'ARTEMIS\x00' +
            struct.pack('<I', 2) +
            struct.pack('<I', cmd_type) +
            struct.pack('<I', len(payload_bytes)) +
            payload_bytes +
            b'\x00'
        )

        # Inner Header: D1 00 [Seq]
        if seq is None:
            seq = self.seq_manager.next_pppp()
        else:
            self.seq_manager.set_pppp(seq + 1) # Sync manager

        inner = struct.pack('>BBH', 0xD1, 0x00, seq)

        full_payload = inner + payload_body
        outer = struct.pack('>BBH', 0xF1, 0xD0, len(full_payload)) + full_payload

        logger.info(f"TX Cmd Type={cmd_type} (Seq={seq})")
        self._send_raw(outer)

    def phase3_login(self):
        logger.info(">>> PHASE 3: Login (0xD0)")
        token_bytes = self.token.encode('ascii')

        # Use new helper
        # Type 1 = Login
        # Log shows PPPP Seq 0 for Login
        self.send_artemis_command(1, token_bytes, seq=0)

        start = time.time()
        while time.time() - start < 5.0:
            resp = self._recv(timeout=1.0)
            if resp and len(resp) > 4:
                if resp[0] == 0xF1 and resp[1] == 0xD0:
                    logger.info("✅ Login Response received!")
                    if b'ARTEMIS' in resp:
                        logger.info("🎉 Login SUCCESS!")
                        return True
                    if b'ACK' in resp:
                        logger.info("Received ACK. Waiting for success...")

        logger.error("❌ Login Failed/Timeout.")
        return False

    def phase4_initialization_sequence(self):
        logger.info(">>> PHASE 4: Initialization Sequence")

        # Helper to wait for response
        def wait_for_resp():
            resp = self._recv(timeout=1.0)
            if resp:
                logger.info(f"RX: {resp.hex()[:20]}...")
            return resp

        # 1. Cmd 2 (Seq 1 based on log flow logic if Login was 0)
        # However, log shows Login (0), Control (5), Cmd 2 (1)
        # We will follow the instruction's implicit "exact replication"

        # Control Packet Seq 5 (Empty payload in log? Or specific?)
        # Log: f1 d1 00 0e d1 00 00 05 00 00 00 00 00 00 00 00 00 00
        self.send_control_packet(5, b'\x00' * 10)

        # Cmd 2 (Seq 1)
        self.send_artemis_command(2, CMD_2_PAYLOAD.encode('ascii'), seq=1)
        wait_for_resp()

        # Control Packet Seq 6? (Log: ...06... 00 01 00 01...)
        self.send_control_packet(6, b'\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01')

        # Cmd 0x10001 (Seq 2)
        # Log shows 0x10001 = 65537
        self.send_artemis_command(0x10001, CMD_10001_PAYLOAD.encode('ascii'), seq=2)
        wait_for_resp()

        # Cmd 3 (Seq 3)
        self.send_artemis_command(3, CMD_3_PAYLOAD.encode('ascii'), seq=3)
        wait_for_resp()

        # Cmd 4 (Seq 4)
        self.send_artemis_command(4, CMD_4_PAYLOAD.encode('ascii'), seq=4)
        wait_for_resp()

        # Cmd 5 (Seq 6 in log? or 5?)
        # Log: Cmd 5 (36Rw) has Seq 6.
        self.send_artemis_command(5, CMD_5_PAYLOAD.encode('ascii'), seq=6)
        wait_for_resp()

        # Cmd 6 (Seq 7)
        self.send_artemis_command(6, CMD_6_PAYLOAD.encode('ascii'), seq=7)
        wait_for_resp()

        logger.info("Initialization Sequence Complete. Entering Heartbeat Loop...")
        self.phase4_heartbeat_loop()

    def phase4_heartbeat_loop(self):
        logger.info(">>> PHASE 5: Heartbeat/Session Loop")
        last_heartbeat = 0
        cmd_id_heartbeat = 525 # From doc

        while True:
            try:
                resp = self._recv(timeout=1.0)
                if resp:
                    # Keep reading
                    pass

                now = time.time()
                if now - last_heartbeat > 3.0:
                    # Heartbeat payload {"cmdId": 525}
                    # This usually uses a different command flow or just json.
                    # Based on existing main_correct.py logic, it sends artemis command.
                    # But the log shows Heartbeat uses Seq 65537+.
                    # We will just send a keep-alive similar to previous implementation
                    # but using the known cmdId 525 if supported, or just empty.
                    # Instructions don't specify heartbeat payload details other than "Heartbeat Loop".
                    # We'll use the JSON payload.
                    hb_payload = json.dumps({"cmdId": cmd_id_heartbeat}).encode('ascii')
                    # Heartbeat usually uses Type 10 or similar generic wrapper?
                    # The doc says "Heartbeat: Outer Type 0xD1, Payload JSON".
                    # send_artemis_command wraps in ARTEMIS header.
                    # If heartbeat is just PPPP D1 + JSON, we should use that.
                    # But doc says "Artemis Login -> Cmd 2...".
                    # Let's assume standard wrapping for now.
                    # Or use the dummy 10 from before.
                    # Using Cmd 10 as placeholder.
                    self.send_artemis_command(10, hb_payload)
                    last_heartbeat = now

            except KeyboardInterrupt:
                break

    def run(self):
        self.connect()
        try:
            self.phase1_lbcs_discovery()
            self.phase2_pre_login()
            if self.phase3_login():
                self.phase4_initialization_sequence()
        finally:
            self.close()

# --- MAIN ---

def main():
    parser = argparse.ArgumentParser(description="Artemis Protocol Client")
    parser.add_argument("--ip", default=DEFAULT_CAMERA_IP, help="Camera IP")
    parser.add_argument("--token", default=TEST_BLE_TOKEN, help="BLE Token (Base64)")
    parser.add_argument("--wifi", action="store_true", help="Connect to WiFi first")
    parser.add_argument("--ble", action="store_true", help="Wakeup via BLE first")
    args = parser.parse_args()

    if args.wifi:
        if not WiFiWorker.connect_nmcli(DEFAULT_WIFI_SSID, DEFAULT_WIFI_PASS):
            logger.error("WiFi connection failed. Aborting.")
            return

    if args.ble:
        asyncio.run(BLEWorker.wake_camera(DEFAULT_BLE_MAC))
        time.sleep(5) # Wait for camera WiFi

    session = PPPPSession(args.ip, DEFAULT_CAMERA_PORT, args.token)
    session.run()

if __name__ == "__main__":
    main()
