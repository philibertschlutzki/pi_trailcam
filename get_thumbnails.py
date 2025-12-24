#!/usr/bin/env python3
"""
Wildkamera Thumbnail Downloader v3.0 - "Mimicry Edition"

CHANGELOG v3.0:
- Architektur-Rewrite: Orientiert sich strikt an den Android-App Logs.
- Sequenz-Management: Repliziert das 0->3->1->2 Muster des Handshakes.
- Background Heartbeat: Sendet alle 2s Heartbeats (Cmd 2/525), wie die App.
- Logging: Schreibt 'app_debug.log' für detaillierte Analyse.
"""

import socket
import struct
import time
import json
import logging
import sys
import argparse
import subprocess
import asyncio
import os
import threading
import base64
import random
from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- CONFIG ---
TARGET_IP = "192.168.43.1"
TARGET_PORTS = [40611, 3333]
FIXED_LOCAL_PORT = 35281
DEFAULT_SSID = "KJK_E0FF"
DEFAULT_PASS = "85087127"
BLE_MAC = "C6:1E:0D:E0:32:E8"

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

# --- CRYPTO ---
PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

# --- LOGGING SETUP ---
logger = logging.getLogger("CamClient")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Console Handler
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)

# File Handler (App Log Mimicry)
fh = logging.FileHandler('app_debug.log', mode='w')
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)

# --- WORKERS ---
class SystemTweaks:
    @staticmethod
    def disable_wifi_powersave():
        try: subprocess.run(["sudo", "iwconfig", "wlan0", "power", "off"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except: pass

class NetworkPinger(threading.Thread):
    def __init__(self, target_ip):
        super().__init__()
        self.target_ip = target_ip
        self.daemon = True
        self.running = True

    def run(self):
        while self.running:
            try:
                subprocess.run(["ping", "-c", "1", "-W", "1", self.target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(1.0)
            except: pass

    def stop(self): self.running = False

class BLEWorker:
    @staticmethod
    async def wake_camera(mac):
        logger.info(f"Suche BLE {mac}...")
        try:
            dev = await BleakScanner.find_device_by_address(mac, timeout=20.0)
            if not dev: return False
            async with BleakClient(dev, timeout=10.0) as client:
                await client.write_gatt_char("00000002-0000-1000-8000-00805f9b34fb", bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]), response=True)
                return True
        except: return False

class WiFiWorker:
    @staticmethod
    def connect(ssid, password):
        SystemTweaks.disable_wifi_powersave()
        try:
            if subprocess.run(["iwgetid", "-r"], capture_output=True, text=True).stdout.strip() == ssid:
                logger.info(f"WLAN bereits mit {ssid} verbunden.")
                return True
        except: pass

        logger.info("Verbinde WLAN...")
        subprocess.run(["sudo", "nmcli", "c", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "d", "wifi", "rescan"], capture_output=True)
        time.sleep(3)
        res = subprocess.run(["sudo", "nmcli", "d", "wifi", "connect", ssid, "password", password, "ifname", "wlan0"], capture_output=True)
        SystemTweaks.disable_wifi_powersave()
        return res.returncode == 0

# --- SESSION ---
class Session:
    def __init__(self):
        self.sock = None
        self.active_port = None
        self.running = True
        self.global_seq = -1 # Startwert für next_seq() -> 0
        self.app_seq = 0
        self.token = None
        self.heartbeat_cnt = 0
        self.heartbeat_active = False
        
        # Locks & Queues
        self.seq_lock = threading.Lock()
        self.sock_lock = threading.Lock()

    def analyze_packet(self, data):
        if len(data) < 8 or data[0] != 0xF1: return f"NON-RUDP ({len(data)} bytes)"
        pkt_type = data[1]
        seq = data[7] if len(data) > 7 else 0
        type_names = {0x41:"DISC_RESP", 0x42:"DATA_FRAG", 0x43:"KEEPALIVE", 0xD0:"DATA", 0xD1:"ACK/CTRL", 0xE0:"ERR", 0xF0:"DISC", 0xF9:"PRE_LOGIN"}
        t_str = type_names.get(pkt_type, f"TYPE_{pkt_type:02X}")
        if pkt_type == 0xD0 and len(data) > 15 and data[8:15] == b'ARTEMIS':
            try:
                cmd = struct.unpack('<I', data[16:20])[0]
                return f"{t_str}(Seq={seq}) -> ARTEMIS(Cmd={cmd})"
            except: pass
        return f"{t_str}(Seq={seq})"

    def log_packet(self, direction, data, desc=""):
        msg = f"{direction} {self.analyze_packet(data)} ({len(data)}b)"
        if desc: msg += f" - {desc}"
        logger.debug(msg)

    def setup_network(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((TARGET_IP, 1))
            local_ip = s.getsockname()[0]
            s.close()
        except: return False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((local_ip, FIXED_LOCAL_PORT))
        self.sock.settimeout(0.5) 
        logger.info(f"Socket gebunden an {local_ip}:{FIXED_LOCAL_PORT}")
        return True

    def get_seq(self, force=None):
        with self.seq_lock:
            if force is not None:
                self.global_seq = force
                return force
            self.global_seq = (self.global_seq + 1) % 255
            return self.global_seq

    def build_rudp_packet(self, packet_type, payload, seq):
        body_len = len(payload) + 4
        header = bytearray([0xF1, packet_type, (body_len >> 8) & 0xFF, body_len & 0xFF, 0xD1, 0x00, 0x00, seq])
        return header + payload

    def build_ack(self, rx_seq):
        payload = bytearray([0x00, rx_seq, 0x00, rx_seq])
        body_len = len(payload) + 4
        header = bytearray([0xF1, 0xD1, (body_len >> 8) & 0xFF, body_len & 0xFF, 0xD1, 0x00, 0x00, 0x00])
        return header + payload

    def send_raw(self, data):
        with self.sock_lock:
            self.sock.sendto(data, (TARGET_IP, self.active_port))

    def heartbeat_loop(self):
        """Sendet Heartbeats im Hintergrund, wie die App"""
        logger.info("💓 Heartbeat Thread gestartet")
        while self.heartbeat_active and self.running:
            try:
                self.heartbeat_cnt = (self.heartbeat_cnt + 1) % 255
                body = bytearray(HEARTBEAT_BODY_START) + bytearray([self.heartbeat_cnt]) + bytearray(HEARTBEAT_PAYLOAD_END)
                # Normales Seq-Inkrement für Heartbeats
                seq = self.get_seq()
                pkt = self.build_rudp_packet(0xD0, body, seq)
                self.send_raw(pkt)
                self.log_packet("📤", pkt, f"Heartbeat Cnt={self.heartbeat_cnt}")
                time.sleep(2.0) # App sendet ca. alle 2s
            except Exception as e:
                logger.error(f"Heartbeat Fehler: {e}")
                break

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
        except: return None

    def send_command(self, cmd_id, payload_dict):
        self.app_seq += 1
        if self.token and cmd_id not in [0, 2]: payload_dict["token"] = str(self.token)
        
        b64_body = base64.b64encode(self.encrypt_json(payload_dict))
        if len(b64_body) % 4 != 0: b64_body += b'=' * (4 - len(b64_body) % 4)
        b64_body += b'\x00'
        
        art_hdr = b'ARTEMIS\x00' + struct.pack('<III', cmd_id, self.app_seq, len(b64_body))
        
        # Sende-Logik mit Retries
        seq = self.get_seq()
        pkt = self.build_rudp_packet(0xD0, art_hdr + b64_body, seq)

        for i in range(5):
            self.send_raw(pkt)
            self.log_packet("📤", pkt, f"CMD {cmd_id} Try={i+1}")
            
            # Kurz warten auf Antwort
            start = time.time()
            while time.time() - start < 1.0:
                try:
                    data, addr = self.sock.recvfrom(65535)
                    self.log_packet("📥", data)
                    
                    if len(data) > 7 and data[0] == 0xF1:
                        if data[1] == 0xD1 and data[7] == seq: return True # ACK
                        if data[1] == 0xD0: # Data Response ist auch ein ACK
                            # Wenn es eine Antwort ist, geben wir sie zurück? 
                            # Hier einfach True, Verarbeitung im Main Loop
                            return True
                except socket.timeout: pass
        return False

    def wait_for_data(self, timeout=5.0):
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = self.sock.recvfrom(65535)
                self.log_packet("📥", data)
                
                if len(data) > 7 and data[0] == 0xF1:
                    # Bestätige alles
                    if data[1] in [0xD0, 0x42]:
                        ack = self.build_ack(data[7])
                        self.send_raw(ack)
                        self.log_packet("📤", ack, f"ACK für {data[7]}")

                    if data[1] == 0xD0 and b'ARTEMIS' in data:
                        return self.decrypt_payload(data)
            except socket.timeout: pass
        return None

    def discover(self):
        logger.info("Starte Discovery...")
        for p in TARGET_PORTS: self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, p))
        
        try:
            data, addr = self.sock.recvfrom(1024)
            if len(data) > 4 and data[0] == 0xF1:
                self.active_port = addr[1]
                logger.info(f"✅ Kamera gefunden auf Port {self.active_port}")
                return True
        except: pass
        return False

    def run(self):
        if not self.setup_network(): return
        NetworkPinger(TARGET_IP).start()
        
        if not self.discover():
            logger.error("❌ Kamera nicht gefunden")
            return

        # --- PRE-LOGIN ---
        logger.info(">>> Sende Pre-Login...")
        payload = { "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }
        enc = AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(pad(json.dumps(payload, separators=(',', ':')).encode(), AES.block_size))
        pkt = struct.pack('>BBH', 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + enc)) + PHASE2_STATIC_HEADER + enc
        self.send_raw(pkt)
        time.sleep(0.5) # Kurze Pause wie im Log

        # --- HANDSHAKE (MIMICRY) ---
        logger.info(">>> Start Handshake (0 -> 3 -> 1)...")
        
        # 1. Hello (Seq 0)
        seq = self.get_seq(force=0)
        pkt = self.build_rudp_packet(0xD0, ARTEMIS_HELLO_BODY, seq)
        self.send_raw(pkt)
        self.log_packet("📤", pkt, "Handshake: Hello")
        time.sleep(0.1)

        # 2. Magic 1 (Seq 3)
        seq = self.get_seq(force=3)
        pkt = self.build_rudp_packet(0xD1, MAGIC_BODY_1, seq)
        self.send_raw(pkt)
        self.log_packet("📤", pkt, "Handshake: Magic 1")
        time.sleep(0.1)

        # 3. Magic 2 (Seq 1)
        seq = self.get_seq(force=1)
        pkt = self.build_rudp_packet(0xD1, MAGIC_BODY_2, seq)
        self.send_raw(pkt)
        self.log_packet("📤", pkt, "Handshake: Magic 2")
        time.sleep(0.1)

        logger.info("✅ Handshake gesendet. Starte Heartbeats...")
        
        # --- START HEARTBEATS (Seq geht ab hier automatisch weiter: 2, 3...) ---
        self.heartbeat_active = True
        hb_thread = threading.Thread(target=self.heartbeat_loop)
        hb_thread.start()
        
        # Warte kurz, damit 1-2 Heartbeats rausgehen (wie im Log)
        time.sleep(1.5)

        # --- LOGIN ---
        logger.info(">>> Sende Login...")
        login_data = {"usrName":"admin","password":"admin","needVideo":0,"needAudio":0,"utcTime":int(time.time()),"supportHeartBeat":True}
        if self.send_command(0, login_data):
            resp = self.wait_for_data()
            if resp and "token" in resp:
                self.token = resp["token"]
                logger.info(f"🎉 LOGIN ERFOLGREICH! Token: {self.token}")
                
                # --- GET INFO ---
                logger.info(">>> Hole Geräte-Info...")
                self.send_command(512, {"cmdId":512}) # GetDevInfo
                self.wait_for_data()

                # --- GET FILES ---
                logger.info(">>> Hole Dateiliste...")
                self.send_command(768, {"cmdId":768, "itemCntPerPage":45, "pageNo":0})
                files_resp = self.wait_for_data()
                if files_resp and "mediaFiles" in files_resp:
                    logger.info(f"✅ {len(files_resp['mediaFiles'])} Dateien gefunden.")
            else:
                logger.error("❌ Kein Token im Login-Response")
        else:
            logger.error("❌ Login-Command nicht bestätigt")

        self.heartbeat_active = False
        self.running = False
        hb_thread.join()
        self.sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ble", action="store_true")
    parser.add_argument("--wifi", action="store_true")
    args = parser.parse_args()

    if args.ble:
        asyncio.run(BLEWorker.wake_camera(BLE_MAC))
        time.sleep(20)
    
    if args.wifi:
        WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS)

    Session().run()
