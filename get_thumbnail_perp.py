#!/usr/bin/env python3
"""
Wildkamera Thumbnail Downloader
Nutzt Stop-and-Wait ARQ mit 3-Phasen-Handshake wie main.py

CHANGELOG v2.8 (2025-12-24):
- TEST: Command-2-als-Login (Handshake = Login)
  * Token wird direkt aus Handshake-Response extrahiert
  * Separater Command-0-Login entfernt
  * Wartet auf verschlüsselte ARTEMIS-Response nach Cmd=2

v2.7 (2025-12-24):
- KRITISCHER FIX: Login mit utcTime-Feld (behebt 0xE0 Error)
  * Login-Payload jetzt identisch mit Android-App
  * cmdId=0 mit usrName, password, needVideo=0, needAudio=0
  * utcTime: Unix-Timestamp (Replay-Schutz der Kamera)
  * supportHeartBeat: true
- Base64-Padding-Korrektur für verschlüsselte Payloads

v2.6 (2025-12-24):
- KRITISCH: Android-App-konformer Thumbnail-Download
  * Keepalive während Thumbnail-Transfer DEAKTIVIERT
  * Batch-Requests: bis zu 45 Thumbnails pro Request
  * Separater Thumbnail-Recv-Thread (parallel zu cmdRecvThread)
  * Response: ACK + dedizierter Datenkanal wie App
  * Token randomisiert wie Android-App
  * JPEG-Parsing mit Marker-Detection

v2.5 (2025-12-24):
- Login-Command korrigiert (cmdId 0 statt 2)
- needVideo/needAudio Pflichtfelder hinzugefügt
- app_seq startet bei 1 (Android-App-konform)

v2.4 (2025-12-24):
- AES-Verschlüsselung: PKCS#7 Padding statt Null-Padding
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

# --- CRYPTO ---
PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("CamClient")

# --- UTILITY FUNCTIONS ---
def hex_dump(data, max_lines=8):
    """Erzeugt formatierte Hex-Dump-Ausgabe"""
    lines = []
    for i in range(0, min(len(data), max_lines * 16), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<47}  {ascii_part}")
    if len(data) > max_lines * 16:
        lines.append(f"... ({len(data) - max_lines * 16} weitere Bytes)")
    return "\n".join(lines)

def analyze_packet(data):
    """Analysiert Pakettyp für Debug-Ausgabe"""
    if len(data) < 8 or data[0] != 0xF1:
        return f"NON-RUDP ({len(data)} bytes)"
    
    pkt_type = data[1]
    seq = data[7] if len(data) > 7 else 0
    
    type_names = {
        0x41: "DISCOVERY_RESP",
        0x42: "DATA_FRAGMENT",
        0x43: "KEEPALIVE",
        0xD0: "DATA",
        0xD1: "CONTROL/ACK",
        0xE0: "ERROR",
        0xF0: "DISCONNECT",
        0xF9: "PRE_LOGIN"
    }
    
    type_str = type_names.get(pkt_type, f"TYPE_{pkt_type:02X}")
    
    if pkt_type == 0xD0 and len(data) > 15 and data[8:15] == b'ARTEMIS':
        try:
            cmd = struct.unpack('<I', data[16:20])[0]
            return f"{type_str}(Seq={seq}) -> ARTEMIS(Cmd={cmd})"
        except:
            return f"{type_str}(Seq={seq}) -> ARTEMIS"
    
    return f"{type_str}(Seq={seq})"

# --- WORKERS ---
class SystemTweaks:
    @staticmethod
    def disable_wifi_powersave():
        try:
            subprocess.run(["sudo", "iwconfig", "wlan0", "power", "off"], 
                         check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except: pass

class NetworkPinger(threading.Thread):
    def __init__(self, target_ip):
        super().__init__()
        self.target_ip = target_ip
        self.daemon = True
        self.running = True

    def run(self):
        logger.info("📡 Background ICMP Ping gestartet.")
        while self.running:
            try:
                subprocess.run(["ping", "-c", "1", "-W", "1", self.target_ip], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(1.0)
            except: pass

    def stop(self):
        self.running = False

class BLEWorker:
    @staticmethod
    async def wake_camera(mac):
        logger.info(f"Suche BLE {mac}...")
        try:
            dev = await BleakScanner.find_device_by_address(mac, timeout=20.0)
            if not dev:
                logger.warning("BLE nicht gefunden (schon wach?).")
                return False
            async with BleakClient(dev, timeout=10.0) as client:
                await client.write_gatt_char("00000002-0000-1000-8000-00805f9b34fb",
                                            bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
                                            response=True)
                logger.info("✅ BLE Wakeup gesendet.")
                return True
        except Exception:
            return False

class WiFiWorker:
    @staticmethod
    def connect(ssid, password):
        SystemTweaks.disable_wifi_powersave()
        try:
            iw_out = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True).stdout.strip()
            if iw_out == ssid:
                logger.info(f"WLAN bereits mit {ssid} verbunden.")
                return True
        except: pass

        logger.info("Verbinde WLAN...")
        subprocess.run(["sudo", "nmcli", "c", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "d", "wifi", "rescan"], capture_output=True)
        time.sleep(3)
        res = subprocess.run(["sudo", "nmcli", "d", "wifi", "connect", ssid, "password", password, "ifname", "wlan0"], capture_output=True)
        SystemTweaks.disable_wifi_powersave()
        if res.returncode == 0:
            logger.info("WLAN verbunden.")
            return True
        return False

# --- SESSION ---
class Session:
    def __init__(self, debug=False):
        self.sock = None
        self.active_port = None
        self.running = True
        self.global_seq = 0
        self.app_seq = 0
        self.debug = debug
        self.tx_count = 0
        self.rx_count = 0
        self.token = None
        self.thumbnail_recv_active = False
        self.thumbnail_buffer = bytearray()
        self.thumbnail_lock = threading.Lock()
        self.thumbnail_count = 0

    def log_tx(self, data, desc=""):
        self.tx_count += 1
        if self.debug:
            logger.debug(f"📤 TX [{self.tx_count}] {analyze_packet(data)} ({len(data)} bytes)")
            if desc:
                logger.debug(f"   └─ {desc}")
            logger.debug(f"\n{hex_dump(data)}")

    def log_rx(self, data, addr, desc=""):
        self.rx_count += 1
        if self.debug:
            logger.debug(f"📥 RX [{self.rx_count}] {analyze_packet(data)} ({len(data)} bytes) from {addr[0]}:{addr[1]}")
            if desc:
                logger.debug(f"   └─ {desc}")
            logger.debug(f"\n{hex_dump(data)}")

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
        if self.global_seq == 0: self.global_seq = 1
        return self.global_seq

    def build_rudp_packet(self, packet_type, payload):
        seq = self.next_seq()
        body_len = len(payload) + 4
        header = bytearray()
        header.append(0xF1)
        header.append(packet_type)
        header.append((body_len >> 8) & 0xFF)
        header.append(body_len & 0xFF)
        header.append(0xD1)
        header.append(0x00)
        header.append(0x00)
        header.append(seq)
        return header + payload, seq

    def build_ack(self, rx_seq):
        payload = bytearray([0x00, rx_seq, 0x00, rx_seq])
        body_len = len(payload) + 4
        header = bytearray()
        header.append(0xF1)
        header.append(0xD1)
        header.append((body_len >> 8) & 0xFF)
        header.append(body_len & 0xFF)
        header.append(0xD1)
        header.append(0x00)
        header.append(0x00)
        header.append(0x00)
        return header + payload

    def discover_and_login(self):
        logger.info("Starte Discovery...")
        for p in TARGET_PORTS:
            pkt = LBCS_PAYLOAD
            self.sock.sendto(pkt, (TARGET_IP, p))
            self.log_tx(pkt, f"LBCS Discovery -> {TARGET_IP}:{p}")

        start = time.time()
        while time.time() - start < 1.5:
            try:
                data, addr = self.sock.recvfrom(1024)
                self.log_rx(data, addr, "Discovery Response")
                
                if len(data) > 4 and data[0] == 0xF1:
                    self.active_port = addr[1]
                    logger.info(f"✅ ANTWORT von {addr[0]}:{addr[1]}")
                    break
            except: pass

        if not self.active_port: return False

        logger.info(f"Sende Pre-Login an {TARGET_IP}:{self.active_port}...")
        payload = { "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }
        enc = AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(pad(json.dumps(payload, separators=(',', ':')).encode(), AES.block_size))
        pkt = struct.pack('>BBH', 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + enc)) + PHASE2_STATIC_HEADER + enc
        
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))
        self.log_tx(pkt, "Phase2 Pre-Login (authentifiziert Kamera)")

        try:
            data, addr = self.sock.recvfrom(1024)
            self.log_rx(data, addr, "Pre-Login Response")
            if data: logger.info("✅ Kamera authentifiziert (0xF9 abgeschlossen).")
        except: pass
        return True

    def encrypt_json(self, obj):
        """Verschlüsselt JSON-Objekt mit AES/ECB/PKCS7"""
        json_str = json.dumps(obj, separators=(',', ':'))
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))
        return encrypted

    def decrypt_payload(self, data):
        try:
            if len(data) < 28: return None
            b64_part = data[28:].split(b'\x00')[0]
            
            # KRITISCH: Padding korrigieren falls nötig
            if len(b64_part) % 4 != 0:
                b64_part += b'=' * (4 - len(b64_part) % 4)
            
            raw_enc = base64.b64decode(b64_part)
            cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(raw_enc), AES.block_size)
            json_str = decrypted.decode('utf-8')
            
            if self.debug:
                logger.debug(f"🔓 Decrypted JSON: {json_str[:200]}...")
            
            return json.loads(json_str)
        except Exception as e:
            if self.debug:
                logger.debug(f"❌ Decrypt failed: {e}")
            return None

    def send_artemis_command(self, cmd_id, payload_dict):
        """Sendet ARTEMIS-Kommando mit korrektem Padding (Android-App-konform)"""
        self.app_seq += 1
        
        # Token nur bei cmdId != 0 UND != 2 anhängen
        if self.token and cmd_id not in [0, 2]:
            payload_dict["token"] = str(self.token)
        
        # JSON verschlüsseln
        enc_data = self.encrypt_json(payload_dict)
        
        # Base64 kodieren und mit \x00 terminieren
        b64_body = base64.b64encode(enc_data)
        
        # KRITISCH: Padding korrigieren falls nötig
        if len(b64_body) % 4 != 0:
            b64_body += b'=' * (4 - len(b64_body) % 4)
        
        b64_body += b'\x00'  # Null-Terminator wie Android-App
        
        if self.debug:
            logger.debug(f"🔐 Encrypted Payload: {b64_body[:60]}")
            if self.token and cmd_id not in [0, 2]:
                logger.debug(f"🔑 Token in JSON: {str(self.token)[:20]}...")
        
        # ARTEMIS-Header aufbauen
        art_hdr = b'ARTEMIS\x00' + struct.pack('<III', cmd_id, self.app_seq, len(b64_body))
        full_payload = art_hdr + b64_body
        
        if self.debug:
            logger.debug(f"📦 ARTEMIS Header: cmd_id={cmd_id}, app_seq={self.app_seq}, payload_len={len(b64_body)}")

        # RUDP-Paket aufbauen und senden
        pkt, seq = self.build_rudp_packet(0xD0, full_payload)

        for attempt in range(10):
            self.sock.sendto(pkt, (TARGET_IP, self.active_port))
            token_info = f"Token={str(self.token)[:8]}..." if self.token else "NoToken"
            self.log_tx(pkt, f"ARTEMIS Cmd={cmd_id}, AppSeq={self.app_seq}, {token_info}, Seq={seq}, Attempt={attempt+1}")

            start = time.time()
            while time.time() - start < 1.5:
                try:
                    data, addr = self.sock.recvfrom(65535)
                    self.log_rx(data, addr)
                    
                    # ACK empfangen?
                    if len(data) > 7 and data[0] == 0xF1 and data[1] == 0xD1:
                        if self.debug:
                            logger.debug(f"✅ ACK für Seq={seq} empfangen")
                        return seq
                except socket.timeout:
                    break

        logger.warning(f"⚠️ Kommando {cmd_id} nicht bestätigt nach 10 Versuchen.")
        return None

    def wait_for_artemis_response(self, timeout=10.0):
        start = time.time()
        logger.info(f"⏳ Warte auf ARTEMIS-Response (max {timeout}s)...")
        
        while time.time() - start < timeout:
            try:
                data, addr = self.sock.recvfrom(65535)
                self.log_rx(data, addr)

                if data[0] != 0xF1:
                    continue
                if data[1] == 0xE0:
                    logger.error(f"❌ Kamera Error 0xE0: {data.hex()}")
                    return None
                if data[1] == 0xF0:
                    logger.error(f"❌ Kamera Disconnect 0xF0: {data.hex()}")
                    return None
                if len(data) < 8:
                    continue

                if data[1] == 0xD0 and b'ARTEMIS' in data:
                    ack = self.build_ack(data[7])
                    self.sock.sendto(ack, (TARGET_IP, self.active_port))
                    self.log_tx(ack, f"ACK für ARTEMIS-Response Seq={data[7]}")

                    resp = self.decrypt_payload(data)
                    if resp:
                        # Token extrahieren wenn vorhanden
                        if "token" in resp and not self.token:
                            self.token = resp["token"]
                            logger.info(f"🔑 TOKEN aus JSON extrahiert: {str(self.token)[:20]}...")
                        
                        logger.info(f"✅ ARTEMIS-Response erhalten: {list(resp.keys())}")
                        return resp

                elif data[1] == 0xD0:
                    ack = self.build_ack(data[7])
                    self.sock.sendto(ack, (TARGET_IP, self.active_port))
                    self.log_tx(ack, f"ACK für D0 Seq={data[7]}")

            except socket.timeout:
                if self.debug:
                    logger.debug("⏱️ Timeout, retry...")
                continue

        logger.warning(f"❌ Timeout: Keine ARTEMIS-Response nach {timeout}s")
        return None

    def thumbnail_recv_thread(self):
        """Dedizierter Thread für Thumbnail-Empfang (Android-App-konform)"""
        logger.info("🧵 Thumbnail recv thread gestartet")
        
        try:
            while self.thumbnail_recv_active:
                try:
                    data, addr = self.sock.recvfrom(65535)
                    
                    if not data:
                        break
                    
                    # Nur Datenpakete (0x42 Fragmente oder 0xD0)
                    if len(data) > 8 and data[0] == 0xF1:
                        pkt_type = data[1]
                        seq = data[7]
                        
                        if pkt_type == 0x42:
                            # Fragment empfangen
                            payload = data[8:]
                            with self.thumbnail_lock:
                                self.thumbnail_buffer.extend(payload)
                            
                            # ACK senden
                            ack = self.build_ack(seq)
                            self.sock.sendto(ack, (TARGET_IP, self.active_port))
                            
                            if self.debug and len(self.thumbnail_buffer) % 10240 == 0:
                                logger.debug(f"🧩 Buffer: {len(self.thumbnail_buffer)} bytes")
                        
                        elif pkt_type == 0xD0 and b'ARTEMIS' in data:
                            # End-Marker
                            ack = self.build_ack(seq)
                            self.sock.sendto(ack, (TARGET_IP, self.active_port))
                            logger.info("🏁 Thumbnail-Transfer abgeschlossen")
                            self.parse_thumbnail_buffer()
                            break
                    
                except socket.timeout:
                    # Timeout ist OK, Thread läuft weiter
                    continue
                    
        except Exception as e:
            logger.error(f"❌ Thumbnail recv thread error: {e}")
        finally:
            logger.info("🧵 Thumbnail recv thread beendet")

    def parse_thumbnail_buffer(self):
        """Extrahiert JPEG-Thumbnails aus Buffer (Android-App Logik)"""
        jpeg_start = b'\xff\xd8'
        jpeg_end = b'\xff\xd9'
        
        with self.thumbnail_lock:
            buffer = bytes(self.thumbnail_buffer)
            self.thumbnail_buffer.clear()
        
        idx = 0
        while True:
            start_idx = buffer.find(jpeg_start, idx)
            if start_idx == -1:
                break
            
            end_idx = buffer.find(jpeg_end, start_idx)
            if end_idx == -1:
                break
            
            jpeg_data = buffer[start_idx:end_idx+2]
            idx = end_idx + 2
            
            self.save_thumbnail(jpeg_data)

    def save_thumbnail(self, jpeg_data):
        """Speichert Thumbnail mit fortlaufender Nummerierung"""
        self.thumbnail_count += 1
        filename = f"thumbnails/thumb_{self.thumbnail_count:04d}.jpg"
        
        os.makedirs("thumbnails", exist_ok=True)
        with open(filename, 'wb') as f:
            f.write(jpeg_data)
        
        logger.info(f"✅ {filename} ({len(jpeg_data)} bytes)")

    def download_thumbnails_batch(self, media_files, batch_size=45):
        """Lädt Thumbnails in Batches (Android-App-Logik: max 45 pro Request)"""
        if not media_files:
            return
        
        total = len(media_files)
        logger.info(f"📥 Starte Batch-Download: {total} Dateien, Batch-Größe={batch_size}")
        
        for batch_idx in range(0, total, batch_size):
            batch = media_files[batch_idx:batch_idx+batch_size]
            logger.info(f"\n{'='*60}")
            logger.info(f"📦 Batch {batch_idx//batch_size + 1}: {len(batch)} Thumbnails")
            
            # Token generieren (wie Android-App)
            token = random.randint(100000000, 999999999)
            
            # Request-Liste aufbauen
            reqs = []
            for item in batch:
                reqs.append({
                    "fileType": item.get("fileType", 0),
                    "dirNum": item.get("dirNum", 100),
                    "mediaNum": item.get("mediaNum")
                })
            
            req = {
                "cmdId": 772,
                "thumbnailReqs": reqs,
                "token": token
            }
            
            # Thumbnail-Empfang aktivieren
            self.thumbnail_recv_active = True
            self.thumbnail_buffer.clear()
            
            # Thread starten VOR dem Request
            recv_thread = threading.Thread(target=self.thumbnail_recv_thread, daemon=True)
            recv_thread.start()
            
            # Request senden
            if not self.send_artemis_command(772, req):
                logger.warning(f"⚠️ Batch-Request fehlgeschlagen")
                self.thumbnail_recv_active = False
                continue
            
            # ACK abwarten
            ack_resp = self.wait_for_artemis_response(timeout=5.0)
            if not ack_resp or ack_resp.get("result") != 0:
                logger.warning(f"⚠️ Batch-ACK fehlgeschlagen")
                self.thumbnail_recv_active = False
                continue
            
            logger.info("✅ Batch-ACK empfangen, warte auf Thumbnails...")
            
            # Warte auf Thread-Completion (max 30s wie Android-App)
            recv_thread.join(timeout=30.0)
            self.thumbnail_recv_active = False
            
            time.sleep(0.5)
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🎉 Download abgeschlossen: {self.thumbnail_count} Thumbnails gespeichert")

    def run(self):
        ping_thread = None
        try:
            if not self.setup_network():
                logger.error("❌ Netzwerk Setup fehlgeschlagen.")
                return

            ping_thread = NetworkPinger(TARGET_IP)
            ping_thread.start()

            if not self.discover_and_login():
                logger.error("❌ Discovery/Login fehlgeschlagen.")
                return

            logger.info(">>> Sende Handshake...")
            if self.debug:
                logger.debug(f"📦 ARTEMIS Hello Body (hex): {ARTEMIS_HELLO_BODY.hex()}")
            
            pkt, seq = self.build_rudp_packet(0xD0, ARTEMIS_HELLO_BODY)
            self.sock.sendto(pkt, (TARGET_IP, self.active_port))
            self.log_tx(pkt, f"Handshake Phase 1: Hello, Seq={seq}")
            time.sleep(0.05)

            pkt, seq = self.build_rudp_packet(0xD1, MAGIC_BODY_1)
            self.sock.sendto(pkt, (TARGET_IP, self.active_port))
            self.log_tx(pkt, f"Handshake Phase 2: Magic1, Seq={seq}")
            time.sleep(0.02)

            pkt, seq = self.build_rudp_packet(0xD1, MAGIC_BODY_2)
            self.sock.sendto(pkt, (TARGET_IP, self.active_port))
            self.log_tx(pkt, f"Handshake Phase 3: Magic2, Seq={seq}")

            # ★★★ NEU: Warte auf Handshake-Completion UND Token ★★★
            logger.info(">>> Warte auf Handshake-Completion UND Token...")
            keepalive_count = 0
            ack_count = 0

            for _ in range(50):
                try:
                    data, addr = self.sock.recvfrom(1024)
                    self.log_rx(data, addr, "Handshake-Wait")
                    
                    if len(data) < 2 or data[0] != 0xF1:
                        continue
                    
                    pkt_type = data[1]
                    
                    # ★★★ NEU: Prüfe auf ARTEMIS-Response mit Token ★★★
                    if pkt_type == 0xD0 and b'ARTEMIS' in data:
                        ack = self.build_ack(data[7])
                        self.sock.sendto(ack, (TARGET_IP, self.active_port))
                        self.log_tx(ack, f"ACK für Handshake ARTEMIS Seq={data[7]}")
                        
                        # Versuche Token zu extrahieren
                        resp = self.decrypt_payload(data)
                        if resp:
                            if "token" in resp:
                                self.token = resp["token"]
                                logger.info(f"✅ TOKEN aus Handshake extrahiert: {str(self.token)[:20]}...")
                                logger.info(f"📋 Handshake-Response: {list(resp.keys())}")
                                break
                            else:
                                logger.info(f"📋 Handshake-Response (kein Token): {list(resp.keys())}")
                    
                    if pkt_type == 0x43:
                        keepalive_count += 1
                        if keepalive_count >= 3:
                            logger.info(f"✅ Session stabil ({keepalive_count} Keepalives)")
                            break
                    
                    elif pkt_type in [0xD0, 0xD1] and len(data) > 7:
                        seq = data[7]
                        ack = self.build_ack(seq)
                        self.sock.sendto(ack, (TARGET_IP, self.active_port))
                        self.log_tx(ack, f"ACK für Handshake-Response Seq={seq}")
                        ack_count += 1
                        
                        if ack_count >= 2 and not self.token:
                            logger.info(f"✅ Handshake abgeschlossen ({ack_count} ACKs gesendet)")
                            time.sleep(0.2)
                            break
                    
                    elif pkt_type == 0xE0:
                        logger.error("❌ Kamera Error 0xE0 während Handshake")
                        return
                    elif pkt_type == 0xF0:
                        logger.error("❌ Kamera Disconnect 0xF0 während Handshake")
                        return
                        
                except socket.timeout:
                    pass
                time.sleep(0.1)

            # ★★★ NEU: Prüfe ob Token nach Handshake vorhanden ★★★
            if self.token:
                logger.info("🎯 Handshake-Token verfügbar, überspringe separaten Login...")
                time.sleep(0.3)
            else:
                logger.warning("⚠️ Kein Token nach Handshake, versuche separaten Login...")
                
                # Fallback: Separater Login wenn nötig
                logger.info("🔑 Sende Login (Command 0)...")
                login_data = {
                    "usrName": "admin",
                    "password": "admin",
                    "needVideo": 0,
                    "needAudio": 0,
                    "utcTime": int(time.time()),
                    "supportHeartBeat": True
                }

                if self.send_artemis_command(0, login_data):
                    login_resp = self.wait_for_artemis_response(timeout=5.0)
                    
                    if not login_resp or login_resp.get("errorCode") != 0:
                        logger.error(f"❌ Login fehlgeschlagen: {login_resp}")
                        return
                    
                    if not self.token:
                        logger.error("❌ Kein Token nach Login erhalten!")
                        return
                else:
                    logger.error("❌ Login-Command nicht bestätigt!")
                    return

            # Ab hier: Token ist verfügbar (aus Handshake oder Login)
            logger.info("📂 Fordere Dateiliste an (Command 768)...")
            time.sleep(0.3)
            
            file_req = {
                "cmdId": 768,
                "itemCntPerPage": 45,
                "pageNo": 0
            }
            
            if self.send_artemis_command(768, file_req):
                file_resp = self.wait_for_artemis_response(timeout=10.0)
                
                if file_resp and "mediaFiles" in file_resp:
                    media_files = file_resp['mediaFiles']
                    logger.info(f"✅ {len(media_files)} Dateien gefunden.")
                    
                    # ★★★ ANDROID-APP-KONFORMER BATCH-DOWNLOAD ★★★
                    self.download_thumbnails_batch(media_files, batch_size=45)
                else:
                    logger.error("❌ Keine Dateiliste erhalten.")
                    if self.debug and file_resp:
                        logger.debug(f"Response war: {file_resp}")
            else:
                logger.error("❌ Dateilisten-Anfrage fehlgeschlagen.")

        except KeyboardInterrupt:
            logger.info("⏹️ Abbruch durch Benutzer.")
        finally:
            self.running = False
            if ping_thread: ping_thread.stop()
            if self.sock: self.sock.close()
            logger.info(f"🔌 Verbindung geschlossen. TX: {self.tx_count}, RX: {self.rx_count}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wildkamera Thumbnail Downloader")
    parser.add_argument("--wifi", action="store_true", help="WiFi Verbindung herstellen")
    parser.add_argument("--ble", action="store_true", help="Kamera via BLE aufwecken")
    parser.add_argument("--debug", action="store_true", help="Debug-Logs aktivieren")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if os.geteuid() != 0:
        logger.warning("⚠️ Bitte als root starten für WLAN/Ping!")

    if args.ble:
        asyncio.run(BLEWorker.wake_camera(BLE_MAC))
        logger.info("⏳ Warte 20s auf WLAN-Bereitschaft...")
        time.sleep(20)

    if args.wifi:
        if not WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS):
            logger.error("❌ WiFi-Verbindung fehlgeschlagen.")
            sys.exit(1)

    Session(debug=args.debug).run()
