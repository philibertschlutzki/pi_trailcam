#!/usr/bin/env python3
"""
Wildkamera Thumbnail Downloader
Nutzt Stop-and-Wait ARQ mit 3-Phasen-Handshake wie main.py
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
from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

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
    
    # Spezielle Marker
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
        self.debug = debug
        self.token = None
        self.tx_count = 0
        self.rx_count = 0

    def log_tx(self, data, desc=""):
        """Loggt gesendete Pakete"""
        self.tx_count += 1
        if self.debug:
            logger.debug(f"📤 TX [{self.tx_count}] {analyze_packet(data)} ({len(data)} bytes)")
            if desc:
                logger.debug(f"   └─ {desc}")
            logger.debug(f"\n{hex_dump(data)}")

    def log_rx(self, data, addr, desc=""):
        """Loggt empfangene Pakete"""
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
        """Baut ACK-Paket OHNE Sequenznummern-Inkrement (fix für 0xE0/0xF0)"""
        payload = bytearray([0x00, rx_seq, 0x00, rx_seq])
        body_len = len(payload) + 4
        header = bytearray()
        header.append(0xF1)
        header.append(0xD1)  # ACK-Typ
        header.append((body_len >> 8) & 0xFF)
        header.append(body_len & 0xFF)
        header.append(0xD1)
        header.append(0x00)
        header.append(0x00)
        header.append(0x00)  # KRITISCH: ACKs benutzen statisch Seq=0
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

        logger.info(f"Sende Login an {TARGET_IP}:{self.active_port}...")
        payload = { "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }
        enc = AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(pad(json.dumps(payload, separators=(',', ':')).encode(), AES.block_size))
        pkt = struct.pack('>BBH', 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + enc)) + PHASE2_STATIC_HEADER + enc
        
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))
        self.log_tx(pkt, "Phase2 Pre-Login")

        try:
            data, addr = self.sock.recvfrom(1024)
            self.log_rx(data, addr, "Pre-Login Response")
            if data: logger.info("✅ Login Antwort erhalten.")
        except: pass
        return True

    def encrypt_json(self, obj):
        """AES-ECB mit Null-Byte Padding"""
        data = json.dumps(obj, separators=(',', ':')).encode('utf-8')
        data_with_null = data + b'\x00'
        pad_len = (16 - (len(data_with_null) % 16)) % 16
        padded_data = data_with_null + (b'\x00' * pad_len)
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        return cipher.encrypt(padded_data)

    def decrypt_payload(self, data):
        try:
            if len(data) < 28: return None
            b64_part = data[28:].split(b'\x00')[0]
            raw_enc = base64.b64decode(b64_part)
            cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
            decrypted = cipher.decrypt(raw_enc)
            json_str = decrypted.decode('utf-8').rstrip('\x00')
            
            if self.debug:
                logger.debug(f"🔓 Decrypted JSON: {json_str[:200]}...")
            
            return json.loads(json_str)
        except Exception as e:
            if self.debug:
                logger.debug(f"❌ Decrypt failed: {e}")
            return None

    def send_artemis_command(self, cmd_id, payload_dict):
        """Sendet ARTEMIS-Kommando mit Stop-and-Wait"""
        if self.token:
            payload_dict["token"] = self.token

        enc_data = self.encrypt_json(payload_dict)
        b64_body = base64.b64encode(enc_data) + b'\x00'
        
        if self.debug:
            logger.debug(f"🔐 Encrypted Payload: {b64_body[:60]}")

        art_hdr = b'ARTEMIS\x00' + struct.pack('<IIHH', cmd_id, cmd_id, len(b64_body), 0)
        full_payload = art_hdr + b64_body

        pkt, seq = self.build_rudp_packet(0xD0, full_payload)

        # Retransmission Loop
        for attempt in range(10):
            self.sock.sendto(pkt, (TARGET_IP, self.active_port))
            self.log_tx(pkt, f"ARTEMIS Cmd={cmd_id}, Seq={seq}, Attempt={attempt+1}")

            start = time.time()
            while time.time() - start < 1.5:
                try:
                    data, addr = self.sock.recvfrom(65535)
                    self.log_rx(data, addr)
                    
                    if len(data) > 7 and data[0] == 0xF1 and data[1] == 0xD1:
                        if self.debug:
                            logger.debug(f"✅ ACK für Seq={seq} empfangen")
                        return seq
                except socket.timeout:
                    break

        logger.warning(f"⚠️ Kommando {cmd_id} nicht bestätigt nach 10 Versuchen.")
        return None

    def wait_for_artemis_response(self, timeout=10.0):
        """Wartet auf ARTEMIS-JSON-Response"""
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

    def reassemble_fragments(self, max_fragments=100, timeout=30.0):
        """Sammelt 0x42-Fragmente bis ARTEMIS-End-Marker"""
        fragments = []
        start = time.time()
        last_activity = time.time()

        logger.info(f"🧩 Starte Fragment-Reassembly (max {timeout}s)...")

        while time.time() - start < timeout and len(fragments) < max_fragments:
            try:
                data, addr = self.sock.recvfrom(65535)
                self.log_rx(data, addr)

                if len(data) < 8 or data[0] != 0xF1:
                    continue

                pkt_type = data[1]
                seq = data[7]

                if pkt_type == 0x42:
                    payload = data[8:]
                    fragments.append((seq, payload))
                    last_activity = time.time()

                    if self.debug and len(fragments) % 10 == 0:
                        logger.debug(f"🧩 {len(fragments)} Fragmente gesammelt...")

                    ack = self.build_ack(seq)
                    self.sock.sendto(ack, (TARGET_IP, self.active_port))
                    self.log_tx(ack, f"ACK Fragment Seq={seq}")

                elif pkt_type == 0xD0 and b'ARTEMIS' in data:
                    ack = self.build_ack(seq)
                    self.sock.sendto(ack, (TARGET_IP, self.active_port))
                    self.log_tx(ack, f"ACK End-Marker Seq={seq}")
                    logger.info(f"🏁 End-Marker empfangen, {len(fragments)} Fragmente total.")
                    break

                elif pkt_type == 0xD0:
                    ack = self.build_ack(seq)
                    self.sock.sendto(ack, (TARGET_IP, self.active_port))
                    self.log_tx(ack, f"ACK D0 Seq={seq}")

                if time.time() - last_activity > 3.0 and fragments:
                    logger.info(f"⏱️ 3s Inaktivität, {len(fragments)} Fragmente gesammelt.")
                    break

            except socket.timeout:
                if fragments and time.time() - last_activity > 2.0:
                    logger.info(f"⏱️ Timeout nach {len(fragments)} Fragmenten.")
                    break
                continue

        if not fragments:
            logger.warning("❌ Keine Fragmente empfangen.")
            return None

        fragments.sort(key=lambda x: x[0])
        total_size = sum(len(f[1]) for f in fragments)
        logger.info(f"✅ {len(fragments)} Fragmente reassembliert ({total_size} bytes total).")
        return b''.join([f[1] for f in fragments])

    def download_thumbnails(self, media_files, output_dir="thumbnails"):
        """Lädt Thumbnails einzeln herunter"""
        if not media_files:
            return

        os.makedirs(output_dir, exist_ok=True)
        success_count = 0

        for idx, item in enumerate(media_files[:50]):
            media_num = item.get("mediaNum")
            logger.info(f"\n{'='*60}")
            logger.info(f"📥 [{idx+1}/{len(media_files[:50])}] Lade Thumbnail {media_num}...")

            req = {
                "cmdId": 772,
                "thumbnailReqs": [{
                    "fileType": item.get("fileType", 0),
                    "dirNum": item.get("dirNum", 100),
                    "mediaNum": media_num
                }]
            }

            if not self.send_artemis_command(772, req):
                logger.warning(f"⚠️ Anfrage für {media_num} fehlgeschlagen.")
                continue

            thumbnail_data = self.reassemble_fragments(timeout=20.0)

            if thumbnail_data and len(thumbnail_data) > 100:
                if thumbnail_data.startswith(b'\xff\xd8\xff'):
                    filename = f"{output_dir}/thumb_{media_num:04d}.jpg"
                    with open(filename, 'wb') as f:
                        f.write(thumbnail_data)
                    logger.info(f"✅ {filename} ({len(thumbnail_data)} bytes)")
                    success_count += 1
                else:
                    logger.warning(f"⚠️ {media_num}: Kein JPEG-Header (erste 10 Bytes: {thumbnail_data[:10].hex()})")
            else:
                logger.warning(f"⚠️ {media_num}: Keine/zu wenig Daten")

            time.sleep(0.5)

        logger.info(f"\n{'='*60}")
        logger.info(f"🎉 {success_count}/{len(media_files[:50])} Thumbnails erfolgreich heruntergeladen.")

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

            # 3-Phasen Handshake
            logger.info(">>> Sende Handshake...")
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

            # FIX: Warte auf Handshake-Completion UND verarbeite ACKs
            logger.info(">>> Warte auf Handshake-Completion...")
            keepalive_count = 0
            ack_count = 0

            for _ in range(50):
                try:
                    data, addr = self.sock.recvfrom(1024)
                    self.log_rx(data, addr, "Handshake-Wait")
                    
                    if len(data) < 2 or data[0] != 0xF1:
                        continue
                    
                    pkt_type = data[1]
                    
                    # Typ 0x43 = Keepalive (optional)
                    if pkt_type == 0x43:
                        keepalive_count += 1
                        if keepalive_count >= 3:
                            logger.info(f"✅ Session stabil ({keepalive_count} Keepalives)")
                            break
                    
                    # Typ 0xD0/0xD1 = Handshake-ACKs → MÜSSEN beantwortet werden!
                    elif pkt_type in [0xD0, 0xD1] and len(data) > 7:
                        seq = data[7]
                        ack = self.build_ack(seq)
                        self.sock.sendto(ack, (TARGET_IP, self.active_port))
                        self.log_tx(ack, f"ACK für Handshake-Response Seq={seq}")
                        ack_count += 1
                        
                        # Nach 2 ACKs ist Handshake komplett
                        if ack_count >= 2:
                            logger.info(f"✅ Handshake abgeschlossen ({ack_count} ACKs gesendet)")
                            time.sleep(0.2)
                            break
                    
                    # 0xE0/0xF0 = Sofortiger Abbruch
                    elif pkt_type == 0xE0:
                        logger.error("❌ Kamera Error 0xE0 während Handshake")
                        return
                    elif pkt_type == 0xF0:
                        logger.error("❌ Kamera Disconnect 0xF0 während Handshake")
                        return
                        
                except socket.timeout:
                    pass
                time.sleep(0.1)

            if ack_count == 0:
                logger.warning("⚠️ Keine Handshake-ACKs empfangen!")

            logger.info(">>> Session etabliert. Starte Datenabruf...")
            time.sleep(0.3)

            # APP LOGIN (Command 2)
            login_data = {
                "cmdId": 2,
                "usrName": "admin",
                "password": "admin",
                "utcTime": 0,
                "supportHeartBeat": True
            }

            if self.send_artemis_command(2, login_data):
                resp = self.wait_for_artemis_response(timeout=10.0)
                if resp and 'token' in resp:
                    self.token = resp['token']
                    logger.info(f"✅ Token erhalten: {self.token[:20]}...")
                else:
                    logger.error("❌ Kein Token erhalten.")
                    if self.debug and resp:
                        logger.debug(f"Response war: {resp}")
                    return
            else:
                logger.error("❌ Login-Command fehlgeschlagen.")
                return

            # Dateiliste abrufen (Command 768)
            logger.info("📂 Fordere Dateiliste an...")
            if self.send_artemis_command(768, {"cmdId": 768, "itemCntPerPage": 45, "pageNo": 0}):
                file_resp = self.wait_for_artemis_response(timeout=10.0)
                if file_resp and "mediaFiles" in file_resp:
                    media_files = file_resp['mediaFiles']
                    logger.info(f"✅ {len(media_files)} Dateien gefunden.")

                    self.download_thumbnails(media_files)
                else:
                    logger.error("❌ Keine Dateiliste erhalten.")
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