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
# Dies ist das Token, das für den Login verwendet wird.
TEST_BLE_TOKEN = "J8WWuQDPmYSLfu/gXAG+UqbBy55KP2iE25QPNofzn040+NI9g7zeXLkIpXpC07SXvosrWsc1m8mxnq6hMiKwePbKJUwvSvqZb6s0sl1sfzh2mtRslV2Nc6tRKoxG/Qj+p3yGl1CC5ARbJJKGBaXcgq7Tnekn+ytw+RLlgoSAMOc="

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
            if resp and len(resp) >= 24 and resp[0] == 0xF1 and resp[1] == 0x43:
                logger.info(f"✅ LBCS Response (0x43) received! Len={len(resp)}")
                self.session_id = resp[20:24]
                logger.info(f"Session ID: {self.session_id.hex()}")
                return True
            time.sleep(0.2)
        logger.warning("⚠️ Phase 1: No response. Continuing...")
        return False

    def phase2_pre_login(self):
        logger.info(">>> PHASE 2: Pre-Login Encryption (0xF9)")
        # RAW Payload (Example/Dummy) - needs 84 bytes
        # Using a pattern since we don't have the exact recording for the full packet
        encrypted_payload = b'\x00' * 84
        packet = struct.pack('>BBH', 0xF1, 0xF9, len(encrypted_payload)) + encrypted_payload

        for i in range(3):
            logger.debug(f"Sending 0xF9 {i+1}/3")
            self._send_raw(packet)
            time.sleep(0.2)
        logger.info("Phase 2 Sent (Blind).")

    def phase3_login(self):
        logger.info(">>> PHASE 3: Login (0xD0)")
        token_bytes = self.token.encode('ascii')

        # Artemis Payload
        # Header: ARTEMIS\x00 (8)
        # Ver: 2 (4, LE)
        # Type: 1 (4, LE)
        # Len: token_len (4, LE)
        # Token
        # Null (1)

        payload_body = (
            b'ARTEMIS\x00' +
            struct.pack('<I', 2) +
            struct.pack('<I', 1) +
            struct.pack('<I', len(token_bytes)) +
            token_bytes +
            b'\x00'
        )

        # Inner Header: D1 00 [Seq]
        seq = self.seq_manager.next_pppp()
        inner = struct.pack('>BBH', 0xD1, 0x00, seq)

        full_payload = inner + payload_body
        outer = struct.pack('>BBH', 0xF1, 0xD0, len(full_payload)) + full_payload

        logger.info(f"Sending Login (Seq={seq}, Len={len(outer)})")
        self._send_raw(outer)

        start = time.time()
        while time.time() - start < 5.0:
            resp = self._recv(timeout=1.0)
            if resp and len(resp) > 4:
                # Check for ACK or Response
                # Assume 0xD0 response
                if resp[0] == 0xF1 and resp[1] == 0xD0:
                    logger.info("✅ Login Response received!")
                    # Check if Success (contains ARTEMIS)
                    if b'ARTEMIS' in resp:
                        logger.info("🎉 Login SUCCESS!")
                        return True
                    if b'ACK' in resp:
                        logger.info("Received ACK. Waiting for success...")

        logger.error("❌ Login Failed/Timeout.")
        return False

    def phase4_heartbeat_loop(self):
        logger.info(">>> PHASE 4/5: Heartbeat/Session Loop")
        # Just send heartbeats periodically
        # Heartbeat Packet?
        # User says: "GetState/Heartbeat: TX: F1 D0 ... Inner ... ARTEMIS ... Base64"
        # Uses Artemis command structure.
        # But also "Simple controller uses raw byte heartbeat F1 E0..." in memory?
        # User prompt says: "Phase 5: Session-Daten (Typ 0xD1) ... GetState/Heartbeat TX F1 D0 ... 41 52 54 ..."
        # So it uses the Artemis JSON command format.

        # We will just listen for now.
        while True:
            try:
                resp = self._recv(timeout=5.0)
                if resp:
                    logger.info(f"RX: {resp.hex()[:20]}...")
                else:
                    logger.info("Heartbeat tick...")
            except KeyboardInterrupt:
                break

    def run(self):
        self.connect()
        try:
            self.phase1_lbcs_discovery()
            self.phase2_pre_login()
            if self.phase3_login():
                self.phase4_heartbeat_loop()
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
