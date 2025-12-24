#!/usr/bin/env python3
"""
Wildkamera Thumbnail Downloader v2.17

CHANGELOG v2.17 (2025-12-24):
- FINALER SEQUENCE FIX: Reset auf Seq=1 nach Handshake
  * Analyse des UDP-Logs ("Golden Trace") zeigte: 
    Hello(0) -> Magic1(3) -> Magic2(1) -> Nächstes Paket ist WIEDER Seq(1)!
  * Das Script sendete bisher Seq(2), was die Kamera ignorierte.
  * FIX: global_seq wird nach Magic2 auf 0 gesetzt (damit next_seq() = 1 ist).
- Strict-Wait für den ersten Heartbeat nach Handshake eingefügt, um Sync zu garantieren.
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

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("CamClient")

# --- UTILITY FUNCTIONS ---
def analyze_packet(data):
    if len(data) < 8 or data[0] != 0xF1:
        return f"NON-RUDP ({len(data)} bytes)"
    
    pkt_type = data[1]
    seq = data[7] if len(data) > 7 else 0
    type_names = {
        0x41: "DISCOVERY_RESP", 0x42: "DATA_FRAGMENT", 0x43: "KEEPALIVE",
        0xD0: "DATA", 0xD1: "CONTROL/ACK", 0xE0: "ERROR", 0xF0: "DISCONNECT", 0xF9: "PRE_LOGIN"
    }
    type_str = type_names.get(pkt_type, f"TYPE_{pkt_type:02X}")
    
    if pkt_type == 0xD0 and len(data) >= 11 and data[8:11] == b'ACK':
         return f"{type_str}(Seq={seq}) -> CAM_HEARTBEAT_ACK (IGNORE)"

    if pkt_type == 0xD0 and len(data) > 15 and data[8:15] == b'ARTEMIS':
        try:
            cmd = struct.unpack('<I', data[16:20])[0]
            return f"{type_str}(Seq={seq}) -> ARTEMIS(Cmd={cmd})"
        except: return f"{type_str}(Seq={seq}) -> ARTEMIS"
    
    return f"{type_str}(Seq={seq})"

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
    def __init__(self, debug=False):
        self.sock = None
        self.active_port = None
        self.running = True
        self.global_seq = -1
        self.app_seq = 0
        self.debug = debug
        self.tx_count = 0
        self.rx_count = 0
        self.token = None
        self.thumbnail_recv_active = False
        self.thumbnail_buffer = bytearray()
        self.thumbnail_lock = threading.Lock()
        self.thumbnail_count = 0
        self.heartbeat_cnt = 0

    def log_tx(self, data, desc=""):
        self.tx_count += 1
        if self.debug:
            logger.debug(f"📤 TX [{self.tx_count}] {analyze_packet(data)} ({len(data)} bytes)")
            if desc: logger.debug(f"   └─ {desc}")

    def log_rx(self, data, addr, desc=""):
        self.rx_count += 1
        if self.debug:
            logger.debug(f"📥 RX [{self.rx_count}] {analyze_packet(data)} ({len(data)} bytes) from {addr[0]}:{addr[1]}")
            if desc: logger.debug(f"   └─ {desc}")

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

    def next_seq(self):
        self.global_seq = (self.global_seq + 1) % 255
        return self.global_seq

    def build_rudp_packet(self, packet_type, payload, force_seq=None):
        if force_seq is not None:
            seq = force_seq
            self.global_seq = seq
        else:
            seq = self.next_seq()
            
        body_len = len(payload) + 4
        header = bytearray([0xF1, packet_type, (body_len >> 8) & 0xFF, body_len & 0xFF, 0xD1, 0x00, 0x00, seq])
        return header + payload, seq

    def build_ack(self, rx_seq):
        payload = bytearray([0x00, rx_seq, 0x00, rx_seq])
        body_len = len(payload) + 4
        header = bytearray([0xF1, 0xD1, (body_len >> 8) & 0xFF, body_len & 0xFF, 0xD1, 0x00, 0x00, 0x00])
        return header + payload

    def send_reliable_packet(self, pkt_type, payload, desc="", max_retries=5, allow_fail=False, force_seq=None):
        pkt, seq = self.build_rudp_packet(pkt_type, payload, force_seq=force_seq)
        
        for attempt in range(max_retries):
            self.sock.sendto(pkt, (TARGET_IP, self.active_port))
            self.log_tx(pkt, f"{desc} (Seq={seq}, Try={attempt+1})")
            
            start = time.time()
            while time.time() - start < 0.8: 
                try:
                    data, addr = self.sock.recvfrom(65535)
                    if len(data) >= 11 and data[8:11] == b'ACK': continue

                    if len(data) > 7 and data[0] == 0xF1:
                        if data[1] == 0xD1: # ACK
                             self.log_rx(data, addr, f"ACK für {desc}")
                             return True
                        if data[1] == 0xD0: # Implizites ACK durch Daten
                             return True
                except socket.timeout: pass
        
        if allow_fail:
            logger.warning(f"⚠️ {desc} nicht bestätigt, fahre trotzdem fort...")
            return True
        
        logger.error(f"❌ {desc} fehlgeschlagen nach {max_retries} Versuchen")
        return False

    def discover_and_login(self):
        logger.info("Starte Discovery...")
        for p in TARGET_PORTS: self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, p))

        start = time.time()
        while time.time() - start < 1.5:
            try:
                data, addr = self.sock.recvfrom(1024)
                if len(data) > 4 and data[0] == 0xF1:
                    self.active_port = addr[1]
                    logger.info(f"✅ ANTWORT von {addr[0]}:{addr[1]}")
                    break
            except: pass

        if not self.active_port: return False

        logger.info(f"Sende Pre-Login...")
        payload = { "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }
        enc = AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(pad(json.dumps(payload, separators=(',', ':')).encode(), AES.block_size))
        pkt = struct.pack('>BBH', 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + enc)) + PHASE2_STATIC_HEADER + enc
        
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))
        self.log_tx(pkt, "Phase2 Pre-Login")
        
        start = time.time()
        while time.time() - start < 2.0:
            try:
                data, addr = self.sock.recvfrom(1024)
                if len(data) > 4 and data[0] == 0xF1:
                    self.log_rx(data, addr, "Pre-Login Response")
                    return True
            except: pass
        return True

    def send_heartbeat(self, force_seq=None, wait_ack=False):
        """Senden eines Heartbeats, optional mit ACK Wait um Sync sicherzustellen"""
        self.heartbeat_cnt = (self.heartbeat_cnt + 1) % 255
        body = bytearray(HEARTBEAT_BODY_START) + bytearray([self.heartbeat_cnt]) + bytearray(HEARTBEAT_PAYLOAD_END)
        pkt, seq = self.build_rudp_packet(0xD0, body, force_seq=force_seq)
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))
        self.log_tx(pkt, f"💓 HEARTBEAT (Cmd=2, Cnt={self.heartbeat_cnt}, RUDP_Seq={seq})")
        
        if wait_ack:
            start = time.time()
            while time.time() - start < 0.5:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    if len(data) > 7 and data[1] == 0xD1:
                        self.log_rx(data, addr, f"ACK für Heartbeat Seq={seq}")
                        return True
                except: pass
        return False

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

    def send_artemis_command(self, cmd_id, payload_dict):
        self.app_seq += 1
        if self.token and cmd_id not in [0, 2]: payload_dict["token"] = str(self.token)
        b64_body = base64.b64encode(self.encrypt_json(payload_dict))
        if len(b64_body) % 4 != 0: b64_body += b'=' * (4 - len(b64_body) % 4)
        b64_body += b'\x00'
        art_hdr = b'ARTEMIS\x00' + struct.pack('<III', cmd_id, self.app_seq, len(b64_body))
        pkt, seq = self.build_rudp_packet(0xD0, art_hdr + b64_body)

        for attempt in range(5):
            self.sock.sendto(pkt, (TARGET_IP, self.active_port))
            self.log_tx(pkt, f"CMD {cmd_id} (Seq={seq}, Try={attempt+1})")
            start = time.time()
            while time.time() - start < 1.0:
                try:
                    data, addr = self.sock.recvfrom(65535)
                    if len(data) >= 11 and data[8:11] == b'ACK': continue
                    if len(data) > 7 and data[0] == 0xF1 and data[1] == 0xD1 and data[7] == seq: return seq
                except socket.timeout: break
        return None

    def wait_for_response(self, timeout=10.0):
        start = time.time()
        last_hb = time.time()
        logger.info(f"⏳ Warte auf Response (max {timeout}s)...")
        while time.time() - start < timeout:
            # Active Heartbeat während wir warten
            if time.time() - last_hb > 1.5:
                self.send_heartbeat()
                last_hb = time.time()
            try:
                data, addr = self.sock.recvfrom(65535)
                self.log_rx(data, addr)
                if data[0] != 0xF1: continue
                if data[1] == 0xD0 and len(data) >= 11 and data[8:11] == b'ACK': continue
                if data[1] == 0xD0:
                    ack = self.build_ack(data[7])
                    self.sock.sendto(ack, (TARGET_IP, self.active_port))
                    if b'ARTEMIS' in data: return self.decrypt_payload(data)
            except socket.timeout: continue
        return None

    def thumbnail_recv_thread(self):
        logger.info("🧵 Thumbnail Thread gestartet")
        while self.thumbnail_recv_active:
            try:
                data, addr = self.sock.recvfrom(65535)
                if not data: break
                if len(data) > 8 and data[0] == 0xF1:
                    pkt_type = data[1]
                    seq = data[7]
                    if pkt_type == 0xD0 and len(data) >= 11 and data[8:11] == b'ACK': continue
                    if pkt_type == 0x42:
                        with self.thumbnail_lock: self.thumbnail_buffer.extend(data[8:])
                        self.sock.sendto(self.build_ack(seq), (TARGET_IP, self.active_port))
                    elif pkt_type == 0xD0 and b'ARTEMIS' in data:
                        self.sock.sendto(self.build_ack(seq), (TARGET_IP, self.active_port))
                        logger.info("🏁 Transfer fertig")
                        self.parse_thumbnail_buffer()
                        break
            except socket.timeout: continue

    def parse_thumbnail_buffer(self):
        with self.thumbnail_lock:
            buf = bytes(self.thumbnail_buffer)
            self.thumbnail_buffer.clear()
        idx = 0
        while True:
            s = buf.find(b'\xff\xd8', idx)
            if s == -1: break
            e = buf.find(b'\xff\xd9', s)
            if e == -1: break
            self.save_thumbnail(buf[s:e+2])
            idx = e+2

    def save_thumbnail(self, data):
        self.thumbnail_count += 1
        fn = f"thumbnails/thumb_{self.thumbnail_count:04d}.jpg"
        os.makedirs("thumbnails", exist_ok=True)
        with open(fn, 'wb') as f: f.write(data)
        logger.info(f"✅ {fn} ({len(data)} bytes)")

    def download_thumbnails_batch(self, media_files, batch_size=45):
        if not media_files: return
        total = len(media_files)
        logger.info(f"📥 Batch-Download: {total} Dateien")
        for batch_idx in range(0, total, batch_size):
            batch = media_files[batch_idx:batch_idx+batch_size]
            token = random.randint(100000000, 999999999)
            reqs = [{"fileType": i.get("fileType", 0), "dirNum": i.get("dirNum", 100), "mediaNum": i.get("mediaNum")} for i in batch]
            req = {"cmdId": 772, "thumbnailReqs": reqs, "token": token}
            self.thumbnail_recv_active = True
            self.thumbnail_buffer.clear()
            t = threading.Thread(target=self.thumbnail_recv_thread, daemon=True)
            t.start()
            if self.send_artemis_command(772, req):
                resp = self.wait_for_response(timeout=5.0)
                if resp and resp.get("result") == 0: t.join(timeout=30.0)
            self.thumbnail_recv_active = False
            time.sleep(0.5)

    def run(self):
        try:
            if not self.setup_network(): return
            NetworkPinger(TARGET_IP).start()
            if not self.discover_and_login(): return

            # --- HANDSHAKE: 0 -> 3 -> 1 ---
            logger.info(">>> Handshake Phase 1 (Hello) [Seq=0]...")
            if not self.send_reliable_packet(0xD0, ARTEMIS_HELLO_BODY, "Hello", force_seq=0): return
            
            logger.info(">>> Handshake Phase 2 (Magic1) [Seq=3]...")
            self.send_reliable_packet(0xD1, MAGIC_BODY_1, "Magic1", force_seq=3, allow_fail=True)
            
            logger.info(">>> Handshake Phase 3 (Magic2) [Seq=1]...")
            self.send_reliable_packet(0xD1, MAGIC_BODY_2, "Magic2", force_seq=1, allow_fail=True)
            
            logger.info("✅ Handshake abgeschlossen. Sende Heartbeat (Seq 1) zur Stabilisierung...")
            
            # CRITICAL SEQ RESET:
            # Nach Magic2 (Seq=1), wird der nächste Counter auf 2 gehen.
            # Aber das UDP Log zeigt, dass das nächste Paket wieder Seq=1 ist (Line 73 nach Line 56).
            # Wir setzen global_seq auf 0, damit next_seq() eine 1 liefert.
            self.global_seq = 0
            
            # Ein zuverlässiger Heartbeat mit Seq=1, um sicherzugehen, dass wir im Sync sind
            if not self.send_heartbeat(wait_ack=True):
                logger.warning("⚠️ Erster Heartbeat nicht bestätigt, versuche Login trotzdem...")

            logger.info(">>> Sende Login (Cmd=0)...")
            login_data = {"usrName":"admin","password":"admin","needVideo":0,"needAudio":0,"utcTime":int(time.time()),"supportHeartBeat":True}
            if self.send_artemis_command(0, login_data):
                resp = self.wait_for_response()
                if resp and "token" in resp:
                    self.token = resp["token"]
                    logger.info(f"🎉 LOGIN ERFOLGREICH! Token: {self.token}")
                else:
                    logger.error(f"❌ Login fehlgeschlagen: {resp}")
                    return
            else:
                logger.error("❌ Login-Command nicht bestätigt.")
                return

            logger.info("📂 Hole Dateiliste...")
            if self.send_artemis_command(768, {"cmdId": 768, "itemCntPerPage": 45, "pageNo": 0}):
                resp = self.wait_for_response()
                if resp and "mediaFiles" in resp:
                    logger.info(f"✅ {len(resp['mediaFiles'])} Dateien gefunden.")
                    self.download_thumbnails_batch(resp['mediaFiles'])
            
        except KeyboardInterrupt: logger.info("Abbruch.")
        finally:
            self.running = False
            if self.sock: self.sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wifi", action="store_true")
    parser.add_argument("--ble", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug: logging.getLogger().setLevel(logging.DEBUG)
    if os.geteuid() != 0: logger.warning("⚠️ Root für WLAN/Ping benötigt!")

    if args.ble:
        asyncio.run(BLEWorker.wake_camera(BLE_MAC))
        time.sleep(20)
    if args.wifi:
        if not WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS): sys.exit(1)

    Session(debug=args.debug).run()
