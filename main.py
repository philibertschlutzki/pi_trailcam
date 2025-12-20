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
        self.pending_acks = {} # Track unacknowledged packets (our TX data packets)

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

class PPPPSession:
    def __init__(self, ip, port, token):
        self.ip = ip
        self.port = port
        self.token = token
        self.sock = None
        self.seq_manager = SequenceManager()
        self.session_id = None

        # ACK Scheduler State
        self.pending_rx_acks = [] # List of received sequences to ACK
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

    def process_outgoing_acks(self):
        """Process pending ACKs and send them based on scheduler logic."""
        if not self.pending_rx_acks:
            return

        now = time.time()
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

        # 3. If single packet, check if we should send immediately (Type 00)
        # To avoid stalling single packets, we can send Type 00 if it's the only one and fresh.
        # But if we want to bundle, we must wait.
        # Issue says: "Type 00 (Immediate ACK): Sofortige Bestätigung nach Empfang eines einzelnen Pakets"
        # So we should send Type 00 immediately if we receive a single packet.
        # But how do we know if more are coming?
        # We can just send Type 00 immediately for every packet if the queue is empty.
        # If the queue is NOT empty, we wait for bundle or timeout.

        if should_send:
            if ack_type == InnerType.ACK_TYPE_01:
                self.send_d1_ack_type_01(self.pending_rx_acks)
            else:
                self.send_d1_ack_type_00(self.pending_rx_acks)

            self.pending_rx_acks = []
            self.first_ack_time = None

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
                            if seq in self.seq_manager.pending_acks:
                                logger.debug(f"ACK received for Seq {seq}")
                                del self.seq_manager.pending_acks[seq]

                    # Handle Data from Camera (0xF1 0xD0) -> Queue ACK
                    elif outer_type == PacketType.DATA:
                        # Parse Inner Header to get Seq
                        if len(data) >= 8:
                            inner = data[4:]
                            # Check for Artemis Header inside
                            # Inner: D1 00 SEQ (4 bytes)
                            inner_magic, inner_type, seq = struct.unpack('>BBH', inner[:4])
                            if inner_magic == 0xD1 and inner_type == 0x00:
                                # Queue ACK
                                if seq not in self.pending_rx_acks:
                                    if not self.pending_rx_acks:
                                        self.first_ack_time = time.time()
                                    self.pending_rx_acks.append(seq)
                                    # Logic to send immediate ACK if it's single
                                    # If we just received 1 packet and queue was empty, we can potentially send immediately
                                    # But to support bundling, we just mark time.
                                    # If we want "Type 00 (Immediate ACK): Sofortige Bestätigung nach Empfang eines einzelnen Pakets"
                                    # AND "Type 01... Gebündelte Bestätigung nach kurzer Wartezeit"
                                    # This implies: If we receive 1 packet, we wait a TINY bit (e.g. 10ms?) to see if more come.
                                    # If no more come, we send Type 00.
                                    # If more come, we send Type 01.
                                    # My scheduler in process_outgoing_acks does exactly this with ack_timeout=50ms.
                                    pass

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

        try:
            encrypted_payload = self.generate_phase2_payload()
            logger.info(f"Generated Dynamic Payload: {len(encrypted_payload)} bytes")
        except Exception as e:
            logger.error(f"Failed to generate payload: {e}")
            return False

        packet = struct.pack('>BBH', 0xF1, PacketType.PRE_LOGIN, len(encrypted_payload)) + encrypted_payload

        for attempt in range(3):
            logger.debug(f"Sending 0xF9 {attempt+1}/3")
            self._send_raw(packet)

            # Wait for specific ACK response: 0xF1 0xD0 ... ACK
            start_wait = time.time()
            while time.time() - start_wait < 1.5:
                resp = self._recv(timeout=0.5)
                # Valid packet minimal length: 4 (Header) + 3 (ACK) = 7.
                if resp and len(resp) >= 7:
                    # Note: Phase 2 ACK often comes as Type D0
                    if resp[0] == 0xF1 and resp[1] == PacketType.DATA and b'ACK' in resp:
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
            seq = self.seq_manager.next_data()
        else:
            # Explicit sequence override
            pass

        inner = struct.pack('>BBH', 0xD1, 0x00, seq)

        full_payload = inner + artemis_header
        outer = struct.pack('>BBH', 0xF1, PacketType.DATA, len(full_payload)) + full_payload

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
        token_bytes = self.token.encode('ascii') + b'\x00'

        # Issue #118 & #121: Integrate Session ID into Login Token
        if self.session_id:
             logger.info(f"Appending Session ID to Login Token: {self.session_id.hex()}")
             token_bytes += self.session_id
        else:
             logger.warning("No Session ID available - login may fail!")

        # Type 1 = Login, Seq 0
        self.send_artemis_command(1, token_bytes, seq=0)

        # Wait for Login Response
        start = time.time()
        while time.time() - start < 5.0:
            resp = self._recv(timeout=0.5)
            self.process_outgoing_acks()

            if resp and len(resp) > 4:
                if resp[0] == 0xF1 and resp[1] == PacketType.DATA:
                    if b'ARTEMIS' in resp:
                         logger.info("🎉 Login SUCCESS (Artemis Response)!")
                         return True

        # If we didn't get Artemis response but got ACK for seq 0, we might still be ok to proceed to Phase 4 check
        if 0 not in self.seq_manager.pending_acks:
             logger.info("✅ Login ACK received (but no explicit response). Proceeding.")
             return True

        logger.error("❌ Login Failed/Timeout.")
        return False

    def phase4_initialization_sequence(self):
        logger.info(">>> PHASE 4: Initialization Sequence")

        # 1. Wait for Login ACK (Seq 0) if not already handled
        if not self.wait_for_ack(0, timeout=3.0):
             # If we timed out waiting for ACK, but maybe we got it earlier.
             pass

        # 2. Control Packet with Seq 3 (Fixed!)
        # The issue says "Control Packet with Seq 3 (fest!)"
        # Since we use a control_seq manager, we should set it or force it.
        # But we also need to respect future increments.
        # If we set it to 3, next will be 4? Or is 3 just for this packet?
        # "Control: Seq 3 (fest!)".
        # Let's force Seq 3.
        self.send_control_packet(3, b'\x00' * 4)

        # 3. Commands with Retry-Logik
        commands = [
            (1, 2, CMD_2_PAYLOAD),           # Retry bis ACK
            (2, 0x10001, CMD_10001_PAYLOAD), # Retry bis ACK
            (3, 3, CMD_3_PAYLOAD),           # Parallel zu Control!
            (4, 4, CMD_4_PAYLOAD),
            (5, 5, CMD_5_PAYLOAD),
            (6, 6, CMD_6_PAYLOAD),
        ]

        for seq, cmd_type, payload in commands:
            retry_count = 0
            max_retries = 3
            success = False

            while retry_count < max_retries:
                # Send Command
                self.send_artemis_command(cmd_type, payload, seq=seq)

                # Wait for ACK with shorter timeout
                if self.wait_for_ack(seq, timeout=0.5):
                    logger.info(f"✅ ACK received for Cmd {cmd_type} (Seq {seq})")
                    success = True
                    break

                logger.warning(f"⚠️ Retry {retry_count+1}/{max_retries} for Cmd {cmd_type} (Seq {seq})")
                retry_count += 1
                time.sleep(0.2)

            if not success:
                logger.error(f"❌ Failed to get ACK for Cmd {cmd_type} (Seq {seq}). Continuing anyway...")

            # Collect other responses/ACKs
            self.collect_responses(timeout=0.2)

        # Update Sequence Managers to follow up after init
        # Data Seq finished at 6. Next should be 7.
        self.seq_manager.set_data(7)
        # Control Seq used 3. Next? Usually control seqs are low or specific.
        # We leave control seq as is or set to 4 if we think it increments.

        logger.info("Initialization Sequence Complete. Entering Heartbeat Loop...")
        self.phase5_heartbeat_loop()

    def phase5_heartbeat_loop(self):
        logger.info(">>> PHASE 5: Heartbeat Loop")
        last_response = time.time()
        last_heartbeat = time.time()

        while True:
            try:
                resp = self._recv(timeout=0.5)
                self.process_outgoing_acks()

                if resp:
                    last_response = time.time()

                    # Handle Discovery packets
                    if resp[0] == 0xF1 and resp[1] in [PacketType.LBCS_REQ, 0x42]:
                        continue

                    # Handle ARTEMIS data
                    if resp[0] == 0xF1 and resp[1] == PacketType.DATA:
                        logger.info(f"RX Artemis Data: {len(resp)} bytes")

                # Send Heartbeat (CMD 5) every 5 seconds
                if time.time() - last_heartbeat > 5.0:
                    logger.debug("Sending Heartbeat (CMD 5)...")
                    self.send_artemis_command(5, CMD_5_PAYLOAD)
                    last_heartbeat = time.time()

                # Check for timeout
                if time.time() - last_response > 15.0:
                    logger.warning("No response for 15s, reconnecting...")
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
