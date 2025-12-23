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

# BLE Konstanten
BLE_UUID_WRITE = "00000002-0000-1000-8000-00805f9b34fb"
BLE_WAKEUP_BYTES = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# Login Token (aus deinem Log)
TEST_BLE_TOKEN = "J8WWuQDPmYSLfu/gXAG+UqbBy55KP2iE25QPNofzn040+NI9g7zeXLkIpXpC07SXvosrWsc1m8mxnq6hMiKwePbKJUwvSvqZb6s0sl1sfzh2mtRslV2Nc6tRKoxG/Qj+p3yGl1CC5ARbJJKGBaXcgq7Tnekn+ytw+RLlgoSAMOc="

# --- CRYPTO KONFIGURATION (PHASE 2) ---
PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

# Statische Payloads (Replay aus Log)
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

# --- PROTOKOLL KONSTANTEN ---
class PacketType:
    LBCS_REQ = 0x41
    LBCS_RESP = 0x43
    DATA = 0xD0
    CONTROL = 0xD1
    PRE_LOGIN = 0xF9
    WAKEUP_1 = 0xE0
    WAKEUP_2 = 0xE1

class InnerType:
    ACK_TYPE_00 = 0x00
    ACK_TYPE_01 = 0x01
    IMAGE_DATA = 0x04

# --- HELPER CLASSES ---

class BLEWorker:
    @staticmethod
    async def wake_camera(mac_address):
        logger.info(f"Attempting BLE Wakeup for {mac_address}...")
        try:
            device = await BleakScanner.find_device_by_address(mac_address, timeout=10.0)
            if not device:
                logger.warning("BLE Device not found (already in WiFi mode?)")
                return False

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
        try:
            res = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
            if ssid in res.stdout.strip():
                logger.info("Already connected to correct WiFi.")
                return True
        except FileNotFoundError:
            pass 

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
        self.data_seq = 0
        self.control_seq = 0
        self.pending_acks = {} 

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
        self.pending_acks[seq] = {
            "timestamp": time.time(),
            "packet": packet_data,
            "retries": 0
        }

    def acknowledge(self, seq):
        if seq in self.pending_acks:
            del self.pending_acks[seq]
            return True
        return False

    def check_retransmissions(self):
        now = time.time()
        for seq, info in list(self.pending_acks.items()):
            if now - info["timestamp"] > 0.5:
                if info["retries"] < 3:
                    info["timestamp"] = now
                    info["retries"] += 1
                    yield (seq, info["packet"])
                else:
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
        self.pending_rx_acks = []

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.settimeout(2.0)
        self.sock.bind(('0.0.0.0', 0))

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
            if data and len(data) > 4:
                self._handle_incoming_packet(data)
            return data
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Recv Error: {e}")
            return None

    def _handle_incoming_packet(self, data):
        outer_magic, outer_type, _ = struct.unpack('>BBH', data[:4])
        
        if outer_magic != 0xF1: return

        if outer_type == PacketType.CONTROL:
            inner = data[4:]
            if len(inner) >= 4:
                i_magic, i_type, _ = struct.unpack('>BBH', inner[:4])
                if i_magic == 0xD1 and i_type in [0, 1]:
                    num_acks = (len(inner) - 4) // 2
                    for i in range(num_acks):
                        offset = 4 + (i * 2)
                        seq = struct.unpack('>H', inner[offset:offset+2])[0]
                        if self.seq_manager.acknowledge(seq):
                            logger.debug(f"ACK received for Seq {seq}")

        elif outer_type == PacketType.DATA:
            inner = data[4:]
            if len(inner) >= 4:
                i_magic, i_type, seq = struct.unpack('>BBH', inner[:4])
                if i_magic == 0xD1:
                    self._send_ack(seq)

    def _send_ack(self, seq_to_ack):
        payload = struct.pack('>H', seq_to_ack)
        seq = self.seq_manager.next_control()
        inner = struct.pack('>BBH', 0xD1, InnerType.ACK_TYPE_00, seq) + payload
        outer = struct.pack('>BBH', 0xF1, PacketType.CONTROL, len(inner)) + inner
        self._send_raw(outer)

    # --- PHASE 0: UDP WAKEUP ---
    def udp_stack_wakeup(self):
        # Sende aggressive Wakeup Pakete
        pkt1 = struct.pack('>BBH', 0xF1, PacketType.WAKEUP_1, 0x0000)
        pkt2 = struct.pack('>BBH', 0xF1, PacketType.WAKEUP_2, 0x0000)
        for _ in range(4):
            self._send_raw(pkt1)
            time.sleep(0.02)
            self._send_raw(pkt2)
            time.sleep(0.02)

    # --- PHASE 1: DISCOVERY ---
    def phase1_lbcs_discovery(self, retries=3, timeout=1.0):
        # Konfigurierbares Discovery für den Loop
        payload = b'LBCS' + b'\x00'*8 + b'CCCJJ' + b'\x00'*3
        packet = struct.pack('>BBH', 0xF1, PacketType.LBCS_REQ, len(payload)) + payload

        for i in range(retries):
            self._send_raw(packet)
            resp = self._recv(timeout=timeout)

            if resp and len(resp) >= 28 and resp[1] == PacketType.LBCS_RESP:
                logger.info(f"✅ LBCS Response received! Len={len(resp)}")
                self.session_id = resp[24:28]
                logger.info(f"Session ID Extracted: {self.session_id.hex()}")
                return True
        return False

    # --- PHASE 2: DYNAMIC CRYPTO ---
    def build_phase2_packet(self):
        payload_dict = {
            "utcTime": int(time.time()),
            "nonce": os.urandom(8).hex()
        }
        json_str = json.dumps(payload_dict, separators=(',', ':'))
        logger.debug(f"Phase 2 JSON: {json_str}")

        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        encrypted_payload = cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))

        full_content = PHASE2_STATIC_HEADER + encrypted_payload
        header = struct.pack('>BBH', 0xF1, PacketType.PRE_LOGIN, len(full_content))
        return header + full_content

    def phase2_pre_login(self):
        logger.info(">>> PHASE 2: Pre-Login Encryption (0xF9)")
        try:
            packet = self.build_phase2_packet()
        except Exception as e:
            logger.error(f"Crypto Error: {e}")
            return False

        for attempt in range(3):
            self._send_raw(packet)
            time.sleep(0.1)
            start = time.time()
            while time.time() - start < 1.0:
                resp = self._recv(timeout=0.1)
                if resp and len(resp) >= 4:
                    if resp[1] == PacketType.DATA or (resp[1] == PacketType.CONTROL and b'ACK' in resp):
                        logger.info("✅ Phase 2 ACK received")
                        return True
        logger.warning("⚠️ Phase 2: No specific ACK received")
        return False 

    # --- PHASE 3 & 4: COMMANDS ---
    def send_artemis_command(self, cmd_type, payload_bytes, seq=None):
        payload_len = len(payload_bytes)
        artemis_header = (
            b'ARTEMIS\x00' +
            struct.pack('<I', 2) +
            struct.pack('<I', cmd_type) +
            struct.pack('<I', payload_len) +
            payload_bytes
        )
        if len(artemis_header) % 4 != 0:
            artemis_header += b'\x00' * (4 - (len(artemis_header) % 4))

        if seq is None: seq = self.seq_manager.next_data()

        inner = struct.pack('>BBH', 0xD1, 0x00, seq)
        full_payload = inner + artemis_header
        outer = struct.pack('>BBH', 0xF1, PacketType.DATA, len(full_payload)) + full_payload

        logger.info(f"TX Cmd Type={cmd_type} (Seq={seq})")
        self._send_raw(outer)
        self.seq_manager.mark_pending(seq, outer)

    def _wait_for_ack(self, expected_seq, timeout=2.0):
        start = time.time()
        while time.time() - start < timeout:
            self._recv(timeout=0.1) 
            if expected_seq not in self.seq_manager.pending_acks:
                logger.info(f"✅ ACK für Seq {expected_seq}")
                return True
        logger.warning(f"⚠️ Timeout ACK Seq {expected_seq}")
        return False

    def execute_artemis_sequence(self):
        logger.info(">>> PHASE 3 & 4: Artemis Login & Init")
        token_bytes = self.token.encode('ascii') + b'\x00'
        if self.session_id:
             logger.info(f"Appending Session ID: {self.session_id.hex()}")
             token_bytes += self.session_id
        
        self.send_artemis_command(1, token_bytes, seq=0)
        self._wait_for_ack(0)

        self.send_artemis_command(2, CMD_2_PAYLOAD, seq=1)
        self._wait_for_ack(1)

        for seq in [2, 3]:
            self.send_artemis_command(10001, CMD_10001_PAYLOAD, seq=seq)
            self._wait_for_ack(seq)

        self.seq_manager.set_data(5)
        self.send_artemis_command(3, CMD_3_PAYLOAD, seq=5)
        self._wait_for_ack(5)

        self.send_artemis_command(4, CMD_4_PAYLOAD, seq=6)
        self._wait_for_ack(6)

        self.send_artemis_command(5, CMD_5_PAYLOAD, seq=7)
        self._wait_for_ack(7)

        self.send_artemis_command(6, CMD_6_PAYLOAD, seq=8)
        self._wait_for_ack(8)
        
        self.seq_manager.set_data(9)

    def run_session(self):
        self.connect()
        try:
            # 1. ROBUSTER DISCOVERY LOOP (Bis zu 40s)
            logger.info("Starte Wakeup/Discovery Loop (Max 40s)...")
            start_time = time.time()
            discovery_success = False

            while time.time() - start_time < 40:
                # Schritt A: Wakeup senden
                self.udp_stack_wakeup()
                
                # Schritt B: Kurz Discovery probieren (nicht blockieren)
                # Wir versuchen es 1x mit 2s Timeout
                if self.phase1_lbcs_discovery(retries=1, timeout=2.0):
                    discovery_success = True
                    break
                
                logger.info("Kamera antwortet noch nicht, erneuter Versuch...")
                # Kurze Pause für den Bootvorgang der Kamera
                time.sleep(1.0)

            if not discovery_success:
                logger.error("❌ TIMEOUT: Kamera hat nach 40s nicht geantwortet.")
                return

            # Ab hier ist die Verbindung stabil
            # 3. Dynamic Encryption Handshake
            if not self.phase2_pre_login():
                return False

            # 4. Login Sequence
            self.execute_artemis_sequence()

            logger.info(">>> PHASE 5: Heartbeat Loop")
            last_heartbeat = time.time()

            while True:
                for seq, packet in self.seq_manager.check_retransmissions():
                    logger.warning(f"Retransmitting Seq {seq}")
                    self._send_raw(packet)

                self._recv(timeout=0.1)

                if time.time() - last_heartbeat > 5.0:
                    self.send_artemis_command(5, CMD_5_PAYLOAD)
                    last_heartbeat = time.time()

        except KeyboardInterrupt:
            logger.info("Stopping...")
        finally:
            self.close()

# --- MAIN ---

def main():
    parser = argparse.ArgumentParser(description="Artemis Client V2 Robust")
    parser.add_argument("--ip", default=DEFAULT_CAMERA_IP, help="Camera IP")
    parser.add_argument("--token", default=TEST_BLE_TOKEN, help="BLE Token")
    parser.add_argument("--wifi", action="store_true", help="Connect WiFi first")
    parser.add_argument("--ble", action="store_true", help="BLE Wakeup first")
    args = parser.parse_args()

    if args.wifi:
        if not WiFiWorker.connect_nmcli(DEFAULT_WIFI_SSID, DEFAULT_WIFI_PASS):
            return

    if args.ble:
        asyncio.run(BLEWorker.wake_camera(DEFAULT_BLE_MAC))
        time.sleep(5)

    session = PPPPSession(args.ip, DEFAULT_CAMERA_PORT, args.token)
    session.run_session()

if __name__ == "__main__":
    main()
