import socket
import struct
import time
import json
import logging
import sys
import argparse
import subprocess
import asyncio
import base64
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
# Note: Instructions say "Base64-Decoding der Payloads"
CMD_2_PAYLOAD = base64.b64decode("y+DDbqMNNnV5LDju3xlEhSWl9peI5eWb2ghmr3wVyEI=")
CMD_10001_PAYLOAD = base64.b64decode("MzlB36X/IVo8ZzI5rG9j1w==")
CMD_3_PAYLOAD = base64.b64decode("I3mbwVIxJQgnSB9GJKNk5Cz4lHNuiNQuetIK1as++bY=")
CMD_4_PAYLOAD = CMD_2_PAYLOAD
CMD_5_PAYLOAD = base64.b64decode("36Rw4/b3Mw4tDnOS/p8mXQ8FnmDnjxA4yMQ9iXTIZQOw=")
CMD_6_PAYLOAD = base64.b64decode("90RH0Mg4PMffYI1fACycdPDFvKRV/22yeiZoDPKRFcyG0jH7mkZCE16ucxWcGAo3ZlwJ+GwTj5vj0L+gvGRmWg==")

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
        self.seq = 0  # Unified sequence counter
        self.pending_acks = {}  # Track unacknowledged packets (our TX)
        self.pending_rx_acks = [] # Track received packets we need to ACK

    def next(self) -> int:
        seq = self.seq
        self.seq = (self.seq + 1) % 65536
        return seq

    def set(self, seq: int):
        self.seq = seq

class PPPPSession:
    def __init__(self, ip, port, token):
        self.ip = ip
        self.port = port
        self.token = token
        self.sock = None
        self.seq_manager = SequenceManager()
        self.session_id = None
        self.last_ack_time = 0

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

    def send_d1_ack_type_00(self, ack_seqs):
        """Sends Type 00 ACK (Immediate/Simple)."""
        # Inner Header: D1 00 [Seq]
        # Payload: List of 2-byte sequences to ACK
        payload = b''
        for s in ack_seqs:
            payload += struct.pack('>H', s)

        seq = self.seq_manager.next()
        inner = struct.pack('>BBH', 0xD1, 0x00, seq)
        full_payload = inner + payload
        outer = struct.pack('>BBH', 0xF1, 0xD1, len(full_payload)) + full_payload
        logger.info(f"TX ACK Type 00 (Seq={seq}) ACKs: {ack_seqs}")
        self._send_raw(outer)

    def send_d1_ack_type_01(self, ack_seqs):
        """Sends Type 01 ACK (Bundled/Delayed)."""
        # Inner Header: D1 01 [Seq]
        payload = b''
        for s in ack_seqs:
            payload += struct.pack('>H', s)

        seq = self.seq_manager.next()
        inner = struct.pack('>BBH', 0xD1, 0x01, seq)
        full_payload = inner + payload
        outer = struct.pack('>BBH', 0xF1, 0xD1, len(full_payload)) + full_payload
        logger.info(f"TX ACK Type 01 (Seq={seq}) ACKs: {ack_seqs}")
        self._send_raw(outer)

    def process_outgoing_acks(self):
        """Process pending ACKs and send them."""
        if not self.seq_manager.pending_rx_acks:
            return

        # Simple strategy:
        # If > 1 ACK pending, use Type 01.
        # If 1 ACK pending, use Type 00.
        # Logic could be more complex based on timing.

        acks = self.seq_manager.pending_rx_acks
        if len(acks) > 1:
            self.send_d1_ack_type_01(acks)
        else:
            self.send_d1_ack_type_00(acks)

        self.seq_manager.pending_rx_acks = []
        self.last_ack_time = time.time()

    def parse_ack_packet(self, data):
        """Parse ACK packet and return acknowledged sequence numbers."""
        if len(data) < 8:
            return []

        # Skip outer header (4 bytes: F1 D1 LEN LEN)
        inner = data[4:]
        if len(inner) < 4:
            return []

        # Inner: D1 00/01 SEQ SEQ
        # The issue description says: "f1 d1 00 08 d1 00 00 02 00 06 00 06 # ACK für Seq 6"
        # Inner: D1 00 00 02 (Header, Seq=2?) -> Payload: 00 06 00 06.
        # "f1 d1 00 0c d1 01 00 04 00 07 00 08 00 09"
        # Inner: D1 01 00 04 (Header, Seq=4?) -> Payload: 00 07 00 08 00 09.

        num_acks = (len(inner) - 4) // 2
        acks = []
        for i in range(num_acks):
            offset = 4 + (i * 2)
            seq = struct.unpack('>H', inner[offset:offset+2])[0]
            acks.append(seq)

        return acks

    def _recv(self, timeout=None):
        if not self.sock: raise ConnectionError("No socket")
        if timeout: self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(4096)

            if data and len(data) > 4:
                # Handle ACKs from Camera (0xF1 0xD1)
                if data[0] == 0xF1 and data[1] == 0xD1:
                    acks = self.parse_ack_packet(data)
                    for seq in acks:
                        if seq in self.seq_manager.pending_acks:
                            logger.debug(f"ACK received for Seq {seq}")
                            del self.seq_manager.pending_acks[seq]

                # Handle Data from Camera (0xF1 0xD0) -> Queue ACK
                elif data[0] == 0xF1 and data[1] == 0xD0:
                    # Parse Inner Header to get Seq
                    # Outer: F1 D0 LEN LEN (4 bytes)
                    # Inner: D1 00 SEQ (4 bytes)
                    if len(data) >= 8:
                        inner = data[4:]
                        if inner[0] == 0xD1 and inner[1] == 0x00:
                            seq = struct.unpack('>H', inner[2:4])[0]
                            # Queue ACK
                            if seq not in self.seq_manager.pending_rx_acks:
                                self.seq_manager.pending_rx_acks.append(seq)

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
            # Response handling should filter for 0x43 type
            # Note: _recv might pick up 0x43, but it might also be consumed by ACK handler if we are not careful
            # But here we are in phase 1, so no other traffic usually.
            if resp and len(resp) >= 28 and resp[0] == 0xF1 and resp[1] == 0x43:
                logger.info(f"✅ LBCS Response (0x43) received! Len={len(resp)}")

                # Extract Session ID (Offset 24, 4 bytes)
                # Issue #115: Session-ID aus 0x43-Response extrahieren und verwenden
                self.session_id = resp[24:28]
                logger.info(f"Session ID Extracted: {self.session_id.hex()}")
                return True
            time.sleep(0.2)
        logger.warning("⚠️ Phase 1: No response. Continuing...")
        return False

    def phase2_pre_login(self):
        logger.info(">>> PHASE 2: Pre-Login Encryption (0xF9)")
        encrypted_payload = PHASE2_ENCRYPTED_PAYLOAD
        packet = struct.pack('>BBH', 0xF1, 0xF9, len(encrypted_payload)) + encrypted_payload

        for attempt in range(3):
            logger.debug(f"Sending 0xF9 {attempt+1}/3")
            self._send_raw(packet)

            # Wait for specific ACK response: 0xF1 0xD0 ... ACK
            start_wait = time.time()
            while time.time() - start_wait < 1.5:
                resp = self._recv(timeout=0.5)
                if resp and len(resp) >= 11:
                    if resp[0] == 0xF1 and resp[1] == 0xD0 and b'ACK' in resp:
                        logger.info("✅ Phase 2 ACK received")
                        return True
                    # Also handle LBCS just in case?
                    if resp[0] == 0xF1 and resp[1] == 0x42:
                        continue # Ignore discovery broadcast

            time.sleep(0.3)

        logger.warning("⚠️ Phase 2: No ACK received after 3 attempts.")
        return False

    def send_artemis_command(self, cmd_type, payload_bytes, seq=None):
        """Constructs and sends an Artemis Command inside PPPP 0xD0."""
        # Artemis Payload Structure:
        # Header: ARTEMIS\x00 (8)
        # Ver: 2 (4, LE)
        # Type: cmd_type (4, LE)
        # Len: payload_len (4, LE)
        # Payload

        payload_len = len(payload_bytes)

        artemis_header = (
            b'ARTEMIS\x00' +
            struct.pack('<I', 2) +
            struct.pack('<I', cmd_type) +
            struct.pack('<I', payload_len) +
            payload_bytes
        )

        # Add null terminator only if needed (padding to 4-byte alignment)
        if len(artemis_header) % 4 != 0:
            padding = b'\x00' * (4 - (len(artemis_header) % 4))
            artemis_header += padding

        # Inner Header: D1 00 [Seq]
        if seq is None:
            seq = self.seq_manager.next()
        else:
            # If explicit seq is provided, we just use it.
            # We do NOT update the manager to avoid side effects on the "unified" counter
            # unless we know for sure it should be synced.
            # Given the non-monotonic nature of the init sequence, we leave the manager alone.
            pass

        inner = struct.pack('>BBH', 0xD1, 0x00, seq)

        full_payload = inner + artemis_header
        outer = struct.pack('>BBH', 0xF1, 0xD0, len(full_payload)) + full_payload

        logger.info(f"TX Cmd Type={cmd_type} (Seq={seq})")
        self._send_raw(outer)

        # Track pending ACK
        self.seq_manager.pending_acks[seq] = time.time()

    def wait_for_ack(self, seq, timeout=2.0):
        start = time.time()
        while time.time() - start < timeout:
            if seq not in self.seq_manager.pending_acks:
                return True
            self._recv(timeout=0.1) # This processes ACKs
            self.process_outgoing_acks() # Send any pending ACKs
        return False

    def collect_responses(self, timeout=0.5):
        """Collect responses for a short period to clear buffers/handle ACKs."""
        start = time.time()
        while time.time() - start < timeout:
            self._recv(timeout=0.1)
            self.process_outgoing_acks()

    def phase3_login(self):
        logger.info(">>> PHASE 3: Login (0xD0)")
        # Token is Base64 string.
        # Issue says: "Login-Befehl mit BLE-Token (Base64-encoded)".
        # And "Payload: 173 Bytes (Token + Padding)".
        # TEST_BLE_TOKEN is 172 chars.
        # We append \x00 to make it 173 bytes (172 + 1).
        # send_artemis_command will then pad it to 176 bytes (173 + 3 padding) to align to 4.

        token_bytes = self.token.encode('ascii') + b'\x00'

        # Type 1 = Login
        # Log shows PPPP Seq 0 for Login
        self.send_artemis_command(1, token_bytes, seq=0)

        # Wait for Login ACK/Response
        # Issue says: "Wait for Login ACK first" in phase 4.

        start = time.time()
        while time.time() - start < 5.0:
            resp = self._recv(timeout=1.0)
            self.process_outgoing_acks()

            if resp and len(resp) > 4:
                if resp[0] == 0xF1 and resp[1] == 0xD0:
                    # Check if it's an ARTEMIS response or just ACK
                    if b'ARTEMIS' in resp:
                         logger.info("🎉 Login SUCCESS (Artemis Response)!")
                         return True

                # If we get an ACK for Seq 0, that's good too
                if 0 not in self.seq_manager.pending_acks:
                    logger.info("✅ Login ACK received.")
                    # But we usually expect a Type 1 response or similar.
                    pass

        logger.error("❌ Login Failed/Timeout.")
        return False

    def phase4_initialization_sequence(self):
        logger.info(">>> PHASE 4: Initialization Sequence")

        # Wait for Login ACK first (Seq 0)
        if not self.wait_for_ack(0, timeout=2.0):
            logger.warning("Login ACK not received, but proceeding...")

        # Control packet Seq 3
        # Issue #115: Control packet MUSS Seq 3 verwenden (nicht 2)
        self.send_control_packet(3, b'\x00' * 4)

        # CMD sequence with proper waiting
        # Structure: (Seq, CmdType, Payload)
        commands = [
            (1, 2, CMD_2_PAYLOAD),           # CMD 2 mit Seq 1
            (2, 0x10001, CMD_10001_PAYLOAD), # CMD 0x10001 mit Seq 2
            (3, 3, CMD_3_PAYLOAD),           # CMD 3 mit Seq 3 (wird überschrieben/parallel)
            (4, 4, CMD_4_PAYLOAD),           # CMD 4 mit Seq 4
            (5, 5, CMD_5_PAYLOAD),           # CMD 5 mit Seq 5
            (6, 6, CMD_6_PAYLOAD),           # CMD 6 mit Seq 6
        ]

        for seq, cmd_type, payload in commands:
            self.send_artemis_command(cmd_type, payload, seq=seq)
            time.sleep(0.2)  # Allow camera to process
            self.collect_responses(timeout=0.5)

        # Control Acknowledgments (mehrere Seq-Ranges) - handled by _recv

        logger.info("Initialization Sequence Complete. Entering Heartbeat Loop...")
        self.phase5_heartbeat_loop()

    def phase5_heartbeat_loop(self):
        logger.info(">>> PHASE 5: Heartbeat Loop")
        last_response = time.time()
        last_heartbeat = time.time()

        while True:
            try:
                resp = self._recv(timeout=1.0)
                self.process_outgoing_acks()

                if resp:
                    last_response = time.time()

                    # Handle Discovery packets
                    if resp[0] == 0xF1 and resp[1] in [0x41, 0x42]:
                        logger.debug("Discovery packet received, ignoring")
                        continue

                    # Handle ARTEMIS data
                    if resp[0] == 0xF1 and resp[1] == 0xD0:
                        logger.info(f"RX Artemis Data: {len(resp)} bytes")

                # Send Heartbeat (CMD 5) every 5 seconds
                if time.time() - last_heartbeat > 5.0:
                    logger.debug("Sending Heartbeat (CMD 5)...")
                    # Use next sequence number from manager
                    self.send_artemis_command(5, CMD_5_PAYLOAD)
                    last_heartbeat = time.time()

                # Check for timeout
                if time.time() - last_response > 10.0:
                    logger.warning("No response for 10s, reconnecting...")
                    break

            except KeyboardInterrupt:
                logger.info("User interrupt")
                break

    def run(self):
        self.connect()
        try:
            if self.phase1_lbcs_discovery():
                pass # Proceed

            if self.phase2_pre_login():
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
