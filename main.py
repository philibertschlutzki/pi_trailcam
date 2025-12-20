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
import os
from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

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
# Issue #118: Dynamische Generierung des Phase2-Payloads
# Verschlüsselung: AES-128-ECB, Key: a01bc23ed45fF56A
PHASE2_KEY = b"a01bc23ed45fF56A"

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

# --- CONSTANTS ---
class PacketType:
    LBCS_REQ = 0x41
    LBCS_RESP = 0x43
    DATA = 0xD0      # Artemis Commands / Login
    CONTROL = 0xD1   # ACKs / Control
    PRE_LOGIN = 0xF9

class InnerType:
    ACK_TYPE_00 = 0x00 # Immediate
    ACK_TYPE_01 = 0x01 # Bundled
    IMAGE_DATA = 0x04

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
        self.data_seq = 0      # For Type 0xD0 (Commands)
        self.control_seq = 0   # For Type 0xD1 (ACKs/Control)
        self.pending_acks = {} # {seq: {"timestamp": time, "packet": bytes, "retries": int}}
        self.max_retries = 3
        self.retry_timeout = 0.2 # 200ms

    def next_data(self) -> int:
        seq = self.data_seq
        self.data_seq = (self.data_seq + 1) % 65536
        return seq

    def next_control(self) -> int:
        seq = self.control_seq
        self.control_seq = (self.control_seq + 1) % 65536
        return seq

    def set_data(self, seq: int):
        self.data_seq = seq

    def mark_pending(self, seq, packet_data):
        """Mark packet as pending ACK"""
        self.pending_acks[seq] = {
            "timestamp": time.time(),
            "packet": packet_data,
            "retries": 0
        }

    def acknowledge(self, seq):
        """Remove ACKed sequence from pending list"""
        if seq in self.pending_acks:
            del self.pending_acks[seq]
            return True
        return False

    def check_retransmissions(self):
        """Checks and yields packets for retransmission"""
        now = time.time()
        for seq, info in list(self.pending_acks.items()):
            if now - info["timestamp"] > self.retry_timeout:
                if info["retries"] < self.max_retries:
                    # Retransmit
                    info["timestamp"] = now
                    info["retries"] += 1
                    yield (seq, info["packet"])
                else:
                    # Max retries reached
                    logger.error(f"Max retries for Seq {seq} reached")
                    del self.pending_acks[seq]

class PPPPSession:
    def __init__(self, ip, port, token):
        self.ip = ip
        self.port = port
        self.token = token
        self.sock = None
        self.seq_manager = SequenceManager()
        self.session_id = None
        self._phase2_payload = None

        # ACK Scheduler State
        self.pending_rx_acks = [] # List of received sequences to ACK
        self.pending_rx_acks_type4 = [] # List of received sequences to ACK with Type 4
        self.first_ack_time = None
        self.ack_bundle_threshold = 10 # Send immediately if > 10
        self.ack_timeout = 0.05 # 50ms per issue request

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.settimeout(2.0)

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
        outer = struct.pack('>BBH', 0xF1, PacketType.CONTROL, len(full_payload)) + full_payload
        logger.info(f"TX Control Packet (Seq={seq}, Len={len(payload)})")
        self._send_raw(outer)

    def send_d1_ack_type_00(self, ack_seqs):
        """Sends Type 00 ACK (Immediate/Simple)."""
        payload = b''
        for s in ack_seqs:
            payload += struct.pack('>H', s)

        seq = self.seq_manager.next_control()
        inner = struct.pack('>BBH', 0xD1, InnerType.ACK_TYPE_00, seq)
        full_payload = inner + payload
        outer = struct.pack('>BBH', 0xF1, PacketType.CONTROL, len(full_payload)) + full_payload
        logger.info(f"TX ACK Type 00 (Seq={seq}) ACKs: {ack_seqs}")
        self._send_raw(outer)

    def send_d1_ack_type_01(self, ack_seqs):
        """Sends Type 01 ACK (Bundled/Delayed)."""
        payload = b''
        for s in ack_seqs:
            payload += struct.pack('>H', s)

        seq = self.seq_manager.next_control()
        inner = struct.pack('>BBH', 0xD1, InnerType.ACK_TYPE_01, seq)
        full_payload = inner + payload
        outer = struct.pack('>BBH', 0xF1, PacketType.CONTROL, len(full_payload)) + full_payload
        logger.info(f"TX ACK Type 01 (Seq={seq}) ACKs: {ack_seqs}")
        self._send_raw(outer)

    def send_d1_ack_type_04(self, ack_seqs):
        """Sends Type 04 ACK (Image Data Acknowledgment)"""
        payload = b''
        for s in ack_seqs:
            payload += struct.pack('>H', s)

        seq = self.seq_manager.next_control()
        inner = struct.pack('>BBH', 0xD1, InnerType.IMAGE_DATA, seq)
        full_payload = inner + payload
        outer = struct.pack('>BBH', 0xF1, PacketType.CONTROL, len(full_payload)) + full_payload
        logger.info(f"TX ACK Type 04 (Seq={seq}) ACKs: {ack_seqs}")
        self._send_raw(outer)

    def process_outgoing_acks(self):
        """Process pending ACKs and send them based on scheduler logic."""
        now = time.time()

        # Handle Type 04 ACKs immediately or bundled?
        # Usually Image ACKs might want to be sent reasonably fast to keep throughput.
        if self.pending_rx_acks_type4:
             self.send_d1_ack_type_04(self.pending_rx_acks_type4)
             self.pending_rx_acks_type4 = []

        if not self.pending_rx_acks:
            return

        should_send = False
        ack_type = InnerType.ACK_TYPE_00

        # Logic:
        # 1. If bundle threshold reached -> Send Type 01 immediately
        if len(self.pending_rx_acks) >= self.ack_bundle_threshold:
            should_send = True
            ack_type = InnerType.ACK_TYPE_01

        # 2. If timeout expired -> Send Type 01 (or 00 if single)
        elif self.first_ack_time and (now - self.first_ack_time > self.ack_timeout):
            should_send = True
            ack_type = InnerType.ACK_TYPE_01 if len(self.pending_rx_acks) > 1 else InnerType.ACK_TYPE_00

        # 3. If single packet, can send Type 00?
        # Leaving as is (timeout based) for now unless immediate requirement.

        if should_send:
            if ack_type == InnerType.ACK_TYPE_01:
                self.send_d1_ack_type_01(self.pending_rx_acks)
            else:
                self.send_d1_ack_type_00(self.pending_rx_acks)

            self.pending_rx_acks = []
            self.first_ack_time = None

    def _queue_ack(self, seq, ack_type):
        if ack_type == InnerType.IMAGE_DATA:
            if seq not in self.pending_rx_acks_type4:
                self.pending_rx_acks_type4.append(seq)
        else:
            if seq not in self.pending_rx_acks:
                if not self.pending_rx_acks:
                    self.first_ack_time = time.time()
                self.pending_rx_acks.append(seq)

    def parse_ack_packet(self, data):
        """Parse ACK packet and return acknowledged sequence numbers."""
        if len(data) < 8:
            return []

        # Skip outer header (4 bytes: F1 D1 LEN LEN)
        inner = data[4:]
        if len(inner) < 4:
            return []

        # Inner: [Magic(1)] [Type(1)] [Seq(2)]
        inner_magic, inner_type, inner_seq = struct.unpack('>BBH', inner[:4])

        if inner_magic != 0xD1:
            return []

        # Parse based on Type
        # Type 00 = Immediate, Type 01 = Bundled, Type 04 = Image?
        if inner_type in [InnerType.ACK_TYPE_00, InnerType.ACK_TYPE_01]:
            num_acks = (len(inner) - 4) // 2
            acks = []
            for i in range(num_acks):
                offset = 4 + (i * 2)
                seq = struct.unpack('>H', inner[offset:offset+2])[0]
                acks.append(seq)
            return acks

        return []

    def _handle_artemis_response(self, data, seq):
        """Parse Artemis Response"""
        # Parse Artemis Header
        # [ARTEMIS\x00] [Ver:4] [Type:4] [Len:4] [Payload]
        if len(data) < 24:
            return

        try:
            ver, resp_type, payload_len = struct.unpack('<III', data[12:24])
            payload = data[24:24+payload_len]

            logger.info(f"ARTEMIS Response: Type={resp_type}, Len={payload_len}")

            if resp_type == 3:  # Response Type 3
                # Parse Base64 Payload
                decoded = base64.b64decode(payload.rstrip(b'\x00'))
                logger.info(f"Decoded Response: {decoded[:100]}...")  # First 100 Bytes

            elif resp_type == 0:  # ACK/Status
                logger.info("Artemis ACK received")
        except Exception as e:
            logger.error(f"Error parsing Artemis response: {e}")

    def _recv(self, timeout=None):
        if not self.sock: raise ConnectionError("No socket")
        if timeout: self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(4096)

            if data and len(data) > 4:
                outer_magic, outer_type, _ = struct.unpack('>BBH', data[:4])

                if outer_magic == 0xF1:
                    # Handle ACKs/Control from Camera (0xF1 0xD1)
                    if outer_type == PacketType.CONTROL:
                        acks = self.parse_ack_packet(data)
                        for seq in acks:
                            if self.seq_manager.acknowledge(seq):
                                logger.debug(f"ACK received for Seq {seq}")

                    # Handle Data from Camera (0xF1 0xD0) -> Queue ACK
                    elif outer_type == PacketType.DATA:
                        # Parse Inner Header to get Seq
                        if len(data) >= 8:
                            inner = data[4:]
                            # Check for Artemis Header inside
                            # Inner: D1 00 SEQ (4 bytes)
                            inner_magic, inner_type, seq = struct.unpack('>BBH', inner[:4])

                            # Erweitert: Prüfe auf Artemis-Response
                            if len(inner) > 12 and inner[4:12] == b'ARTEMIS\x00':
                                self._handle_artemis_response(inner, seq)

                            if inner_magic == 0xD1:
                                if inner_type in [0x00, 0x01]:
                                    self._queue_ack(seq, InnerType.ACK_TYPE_01)
                                elif inner_type == 0x04:
                                    self._queue_ack(seq, InnerType.IMAGE_DATA)
                                else:
                                    self._queue_ack(seq, InnerType.ACK_TYPE_00)

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
        packet = struct.pack('>BBH', 0xF1, PacketType.LBCS_REQ, len(payload)) + payload

        for i in range(3):
            logger.debug(f"Sending LBCS {i+1}/3")
            self._send_raw(packet)
            resp = self._recv(timeout=0.5)

            if resp and len(resp) >= 28 and resp[0] == 0xF1 and resp[1] == PacketType.LBCS_RESP:
                logger.info(f"✅ LBCS Response (0x43) received! Len={len(resp)}")

                # Extract Session ID (Offset 24, 4 bytes)
                self.session_id = resp[24:28]
                logger.info(f"Session ID Extracted: {self.session_id.hex()}")
                return True
            time.sleep(0.2)
        logger.warning("⚠️ Phase 1: No response. Continuing...")
        return False

    def generate_phase2_payload(self):
        """Generates the encrypted Phase 2 payload using AES-128-ECB."""
        json_cmd = {
            "utcTime": int(time.time()),
            "nonce": os.urandom(8).hex()
        }
        json_str = json.dumps(json_cmd).replace(" ", "")
        logger.debug(f"Phase 2 JSON (Plain): {json_str}")

        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))
        return encrypted

    def phase2_pre_login(self):
        logger.info(">>> PHASE 2: Pre-Login Encryption (0xF9)")

        # Generiere Payload nur einmal
        if self._phase2_payload is None:
            try:
                self._phase2_payload = self.generate_phase2_payload()
                logger.info(f"Generated Cached Payload: {len(self._phase2_payload)} bytes")
            except Exception as e:
                logger.error(f"Failed to generate payload: {e}")
                return False

        packet = struct.pack('>BBH', 0xF1, PacketType.PRE_LOGIN, len(self._phase2_payload)) + self._phase2_payload

        for attempt in range(3):
            logger.debug(f"Sending 0xF9 {attempt+1}/3")
            self._send_raw(packet)
            # Short pause between retries if no immediate response
            time.sleep(0.05)

        # Wait for ACK
        start_wait = time.time()
        while time.time() - start_wait < 1.5:
            resp = self._recv(timeout=0.5)
            if resp and len(resp) >= 7:
                if resp[0] == 0xF1 and resp[1] == PacketType.DATA and b'ACK' in resp:
                    logger.info("✅ Phase 2 ACK received")
                    return True

        logger.warning("⚠️ Phase 2: No ACK received")
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
            seq = self.seq_manager.next_data()
        else:
            # Explicit sequence override
            pass

        inner = struct.pack('>BBH', 0xD1, 0x00, seq)

        full_payload = inner + artemis_header
        outer = struct.pack('>BBH', 0xF1, PacketType.DATA, len(full_payload)) + full_payload

        logger.info(f"TX Cmd Type={cmd_type} (Seq={seq})")
        self._send_raw(outer)

        # Mark pending
        self.seq_manager.mark_pending(seq, outer)

    def _wait_for_ack(self, expected_seq, timeout=2.0):
        """Wartet auf ACK für eine bestimmte Sequenznummer"""
        start = time.time()
        while time.time() - start < timeout:
            # Check pending_acks
            self.process_outgoing_acks()  # Sende eigene ACKs
            self._recv(timeout=0.1)  # Empfange und parse ACKs

            if expected_seq not in self.seq_manager.pending_acks:
                logger.info(f"✅ ACK für Seq {expected_seq} empfangen")
                return True

        logger.warning(f"⚠️ Timeout für ACK Seq {expected_seq}")
        return False

    def execute_artemis_sequence(self):
        """Führt die komplette Befehlssequenz aus den Logs aus"""
        logger.info(">>> PHASE 3 & 4: Artemis Login & Initialization Sequence")

        # Prepare Login Token
        token_bytes = self.token.encode('ascii') + b'\x00'
        if self.session_id:
             logger.info(f"Appending Session ID to Login Token: {self.session_id.hex()}")
             token_bytes += self.session_id
        else:
             logger.warning("No Session ID available - login may fail!")

        # CMD 1: Login (Seq 0x00)
        self.send_artemis_command(1, token_bytes, seq=0)
        self._wait_for_ack(0)

        # CMD 2: Encrypted Payload (Seq 0x01)
        self.send_artemis_command(2, CMD_2_PAYLOAD, seq=1)
        self._wait_for_ack(1)

        # CMD 10001: Wiederholtes Kommando (Seq 0x02 und 0x03)
        for seq in [2, 3]:
            self.send_artemis_command(10001, CMD_10001_PAYLOAD, seq=seq)
            self._wait_for_ack(seq)

        # CMD 3: Encrypted (Seq 0x05 - Achtung: Sprung in Seq!)
        self.seq_manager.set_data(5)  # Seq manuell setzen
        self.send_artemis_command(3, CMD_3_PAYLOAD, seq=5)
        self._wait_for_ack(5)

        # CMD 4: Wie CMD 2 (Seq 0x06)
        self.send_artemis_command(4, CMD_4_PAYLOAD, seq=6)
        self._wait_for_ack(6)

        # CMD 5: Base64 Payload (Seq 0x07)
        self.send_artemis_command(5, CMD_5_PAYLOAD, seq=7)
        self._wait_for_ack(7)

        # CMD 6: Base64 Payload (Seq 0x08)
        self.send_artemis_command(6, CMD_6_PAYLOAD, seq=8)
        self._wait_for_ack(8)

        # After sequence, set data seq for future (Seq 8 was last, so next is 9)
        self.seq_manager.set_data(9)

    def run_session(self):
        """Hauptschleife mit Retransmission-Support"""
        self.connect()

        try:
            if not self.phase1_lbcs_discovery():
                return False

            if not self.phase2_pre_login():
                return False

            # Artemis-Sequenz
            self.execute_artemis_sequence()

            logger.info(">>> PHASE 5: Heartbeat & Event Loop")
            last_heartbeat = time.time()

            # Event-Loop für ACKs und Retransmissions
            while True:
                # Prüfe auf Retransmissions
                for seq, packet in self.seq_manager.check_retransmissions():
                    logger.warning(f"Retransmitting Seq {seq}")
                    self._send_raw(packet)

                # Empfange und verarbeite
                self._recv(timeout=0.1)

                # Sende ausstehende ACKs
                self.process_outgoing_acks()

                # Heartbeat every 5s
                if time.time() - last_heartbeat > 5.0:
                    self.send_artemis_command(5, CMD_5_PAYLOAD)
                    last_heartbeat = time.time()

        except KeyboardInterrupt:
            logger.info("Stopping...")
        finally:
            self.close()
        return True

    def run(self):
        # Wrapper for existing main call
        self.run_session()

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
