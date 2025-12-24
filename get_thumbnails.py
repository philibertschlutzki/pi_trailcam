#!/usr/bin/env python3
"""
Wildkamera Thumbnail Downloader v3.3 - "Response Filter" Edition

CHANGELOG v3.3:
- FIX: Decrypt Error ("Incorrect padding") behoben.
  * Das Script hat eingehende Cmd=9 Pakete (Keepalive) fälschlicherweise als Login-Antwort interpretiert.
  * wait_for_packet() filtert nun auf die erwartete Cmd-ID im Artemis-Header.
- OPTIMIERUNG: Robustere Behandlung von "versprengten" Paketen.
"""

import socket
import struct
import time
import json
import logging
import sys
import argparse
import subprocess
import os
import base64
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- CONFIG ---
TARGET_IP = "192.168.43.1"
TARGET_PORTS = [40611, 3333]
FIXED_LOCAL_PORT = 35281
DEFAULT_SSID = "KJK_E0FF"
DEFAULT_PASS = "85087127"

# --- PAYLOADS ---
LBCS_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")
ARTEMIS_HELLO_BODY = bytes.fromhex(
    "415254454d495300"
    "0200000001000000ad0000004a385757"
    "755144506d59534c66752f675841472b"
    "557162427935354b5032694532355150"
    "4e6f667a6e3034302b4e493967377a65"
    "584c6b497058704330375358766f7372"
    "577363316d386d786e7136684d694b77"
    "6550624b4a5577765376715a62367330"
    "736c3173667a68335335307070307475"
    "324b6577693050694463765871584d32"
    "68506c4e6c6847536933465541762b50"
    "647935682f7278382b47743737546845"
    "2b726431446d453d00"
)
MAGIC_BODY_1 = bytes.fromhex("000000000000")
MAGIC_BODY_2 = bytes.fromhex("0000")
HEARTBEAT_BODY_START = bytes.fromhex("415254454d49530002000000") 
HEARTBEAT_PAYLOAD_END = bytes.fromhex("000100190000004d7a6c423336582f49566f385a7a49357247396a31773d3d00")

PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

# --- LOGGING ---
class UnbufferedStream:
    def __init__(self, stream): self.stream = stream
    def write(self, data): self.stream.write(data); self.stream.flush()
    def __getattr__(self, attr): return getattr(self.stream, attr)

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app_debug.log", mode='w', encoding='utf-8'),
        logging.StreamHandler(UnbufferedStream(sys.stdout))
    ]
)
logger = logging.getLogger("CamClient")

# --- WORKERS ---
class WiFiWorker:
    @staticmethod
    def connect(ssid, password):
        try:
            subprocess.run(["sudo", "iwconfig", "wlan0", "power", "off"], check=False, stdout=subprocess.DEVNULL)
            if subprocess.run(["iwgetid", "-r"], capture_output=True, text=True).stdout.strip() == ssid:
                logger.info(f"WLAN bereits mit {ssid} verbunden.")
                return True
        except: pass
        logger.info("Verbinde WLAN...")
        subprocess.run(["sudo", "nmcli", "c", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "d", "wifi", "rescan"], capture_output=True)
        time.sleep(3)
        res = subprocess.run(["sudo", "nmcli", "d", "wifi", "connect", ssid, "password", password, "ifname", "wlan0"], capture_output=True)
        return res.returncode == 0

class Session:
    def __init__(self):
        self.sock = None
        self.active_port = None
        self.global_seq = -1 
        self.app_seq = 0
        self.token = None
        self.heartbeat_cnt = 0
        self.last_heartbeat_time = 0

    def analyze_packet(self, data):
        if len(data) < 8 or data[0] != 0xF1: return f"NON-RUDP ({len(data)}b)"
        pkt_type = data[1]
        seq = data[7] if len(data) > 7 else 0
        type_names = {0x41:"DISC", 0x42:"FRAG", 0x43:"KEEPALIVE", 0xD0:"DATA", 0xD1:"ACK", 0xE0:"ERR", 0xF0:"DISC", 0xF9:"PRE"}
        t_str = type_names.get(pkt_type, f"{pkt_type:02X}")
        
        info = f"{t_str}(Seq={seq})"
        if pkt_type == 0xD0 and len(data) > 15 and data[8:15] == b'ARTEMIS':
            try:
                cmd = struct.unpack('<I', data[16:20])[0]
                info += f" ARTEMIS(Cmd={cmd})"
            except: pass
        return info

    def get_artemis_cmd_id(self, data):
        """Extrahiert die Command ID aus einem Artemis Paket"""
        if len(data) > 20 and b'ARTEMIS' in data:
            try:
                # Header: F1 D0 ... ARTEMIS\x00 (8 bytes) + CmdID (4 bytes)
                # Artemis Magic Startet bei Index 8
                # Cmd ID ist bei Index 16 (8+8)
                return struct.unpack('<I', data[16:20])[0]
            except: pass
        return None

    def setup_network(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((TARGET_IP, 1))
            local_ip = s.getsockname()[0]
            s.close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((local_ip, FIXED_LOCAL_PORT))
            self.sock.settimeout(0.1) 
            logger.info(f"Socket: {local_ip}:{FIXED_LOCAL_PORT}")
            return True
        except Exception as e:
            logger.error(f"Netzwerkfehler: {e}")
            return False

    def next_seq(self):
        self.global_seq = (self.global_seq + 1) % 255
        return self.global_seq

    def build_packet(self, packet_type, payload, force_seq=None):
        if force_seq is not None:
            seq = force_seq
            self.global_seq = seq
        else:
            seq = self.next_seq()
        body_len = len(payload) + 4
        header = bytearray([0xF1, packet_type, (body_len >> 8) & 0xFF, body_len & 0xFF, 0xD1, 0x00, 0x00, seq])
        return header + payload, seq

    def send_raw(self, data, desc=""):
        try:
            self.sock.sendto(data, (TARGET_IP, self.active_port))
            logger.debug(f"📤 {self.analyze_packet(data)} {desc}")
        except: pass

    def send_ack(self, seq):
        payload = bytearray([0x00, seq, 0x00, seq])
        header = bytearray([0xF1, 0xD1, (body_len := len(payload) + 4) >> 8, body_len & 0xFF, 0xD1, 0x00, 0x00, 0x00])
        self.send_raw(header + payload, desc=f"ACK for {seq}")

    def send_heartbeat(self):
        if time.time() - self.last_heartbeat_time < 1.5: return
        self.heartbeat_cnt = (self.heartbeat_cnt + 1) % 255
        body = bytearray(HEARTBEAT_BODY_START) + bytearray([self.heartbeat_cnt]) + bytearray(HEARTBEAT_PAYLOAD_END)
        pkt, seq = self.build_packet(0xD0, body)
        self.send_raw(pkt, desc=f"Heartbeat AppCnt={self.heartbeat_cnt}")
        self.last_heartbeat_time = time.time()

    def wait_for_packet(self, timeout=1.0, expected_seq=None, wait_for_cmd=None):
        """
        Zentrale Empfangs-Schleife mit SMART ACK Logic und CMD-Filter.
        """
        start = time.time()
        while time.time() - start < timeout:
            if self.active_port and self.global_seq > 1: self.send_heartbeat()

            try:
                data, addr = self.sock.recvfrom(65535)
                if len(data) < 8 or data[0] != 0xF1: continue
                
                pkt_type = data[1]
                rx_seq = data[7] if len(data) > 7 else 0
                logger.debug(f"📥 {self.analyze_packet(data)}")

                if pkt_type in [0xD0, 0x42]:
                    if not (len(data) >= 11 and data[8:11] == b'ACK'):
                        self.send_ack(rx_seq)
                        
                        # Prüfen ob wir auf spezifisches Kommando warten (z.B. Login Response Cmd=0)
                        if wait_for_cmd is not None:
                            recv_cmd = self.get_artemis_cmd_id(data)
                            if recv_cmd == wait_for_cmd:
                                return data
                            else:
                                if recv_cmd is not None:
                                    logger.debug(f"⚠️ Ignoriere Cmd {recv_cmd} (warte auf {wait_for_cmd})")
                                continue # Weitersuchen

                        # Generische Daten-Warte-Logik
                        if wait_for_cmd is None and expected_seq is None:
                             if b'ARTEMIS' in data: return data

                        if expected_seq is not None: return True

                if expected_seq is not None and pkt_type == 0xD1:
                    if rx_seq == expected_seq: return True
                    if rx_seq == (expected_seq + 1) % 255: return True 
                    if rx_seq == 0: return True 

            except socket.timeout: pass
        return None

    def encrypt_json(self, obj):
        return AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(pad(json.dumps(obj, separators=(',', ':')).encode('utf-8'), AES.block_size))

    def decrypt_payload(self, data):
        try:
            if len(data) < 28: return None
            b64_part = data[28:].split(b'\x00')[0]
            if len(b64_part) % 4 != 0: b64_part += b'=' * (4 - len(b64_part) % 4)
            raw = base64.b64decode(b64_part)
            decrypted = unpad(AES.new(PHASE2_KEY, AES.MODE_ECB).decrypt(raw), AES.block_size)
            return json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            logger.error(f"Decrypt Error: {e}")
            return None

    def run(self):
        if not self.setup_network(): return
        
        logger.info(">>> Discovery...")
        for p in TARGET_PORTS: self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, p))
        start = time.time()
        while time.time() - start < 2.0:
            try:
                data, addr = self.sock.recvfrom(1024)
                if len(data) > 4 and data[0] == 0xF1:
                    self.active_port = addr[1]
                    logger.info(f"✅ Kamera: {addr}")
                    break
            except: pass
        if not self.active_port: logger.error("❌ Kamera nicht gefunden"); return

        logger.info(">>> Pre-Login...")
        payload = { "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }
        enc = AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(pad(json.dumps(payload, separators=(',', ':')).encode(), AES.block_size))
        pkt = struct.pack('>BBH', 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + enc)) + PHASE2_STATIC_HEADER + enc
        self.send_raw(pkt, "Pre-Login")
        self.wait_for_packet(timeout=2.0)

        logger.info(">>> Handshake Step 1: Hello (Seq 0)")
        pkt, _ = self.build_packet(0xD0, ARTEMIS_HELLO_BODY, force_seq=0)
        self.send_raw(pkt, "Hello")
        if not self.wait_for_packet(timeout=1.0, expected_seq=0):
            logger.error("❌ Hello nicht bestätigt")
            return

        logger.info(">>> Handshake Step 2: Magic 1 (Seq 3)")
        pkt, _ = self.build_packet(0xD1, MAGIC_BODY_1, force_seq=3)
        self.send_raw(pkt, "Magic 1")
        time.sleep(0.1)

        logger.info(">>> Handshake Step 3: Magic 2 (Seq 1)")
        pkt, _ = self.build_packet(0xD1, MAGIC_BODY_2, force_seq=1)
        self.send_raw(pkt, "Magic 2")
        time.sleep(0.1)

        self.global_seq = 1

        logger.info(">>> Stabilisierung (Heartbeats)...")
        for i in range(3):
            self.send_heartbeat()
            self.wait_for_packet(timeout=0.5)

        logger.info(">>> Login (Seq 5)...")
        self.app_seq += 1
        login_data = {"cmdId": 0, "usrName": "admin", "password": "admin", "needVideo": 0, "needAudio": 0, "utcTime": int(time.time()), "supportHeartBeat": True}
        b64_body = base64.b64encode(self.encrypt_json(login_data)) + b'\x00'
        art_hdr = b'ARTEMIS\x00' + struct.pack('<III', 0, self.app_seq, len(b64_body))
        pkt, seq = self.build_packet(0xD0, art_hdr + b64_body)
        self.send_raw(pkt, "Login")
        
        # FIX: Warten explizit auf Cmd 0 (Login Response)
        resp_pkt = self.wait_for_packet(timeout=5.0, wait_for_cmd=0)
        
        if resp_pkt:
            resp = self.decrypt_payload(resp_pkt)
            if resp and "token" in resp:
                self.token = resp["token"]
                logger.info(f"🎉🎉 LOGIN ERFOLGREICH! Token: {self.token}")
            else:
                logger.error(f"❌ Login Antwort ungültig: {resp}")
        else:
            logger.error("❌ Login Timeout")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wifi", action="store_true")
    args = parser.parse_args()
    if args.wifi: WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS)
    Session().run()
