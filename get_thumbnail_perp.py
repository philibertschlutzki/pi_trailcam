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
from Crypto.Util.Padding import pad, unpad

# --- CONFIG ---
TARGET_IP = "192.168.43.1"
TARGET_PORTS = [40611, 3333]
FIXED_LOCAL_PORT = 35281

DEFAULT_SSID = "KJK_E0FF"
DEFAULT_PASS = "85087127"
BLE_MAC = "C6:1E:0D:E0:32:E8"

# --- CRYPTO & CONSTANTS ---
PHASE2_KEY = b"a01bc23ed45fF56A"
# Header für Pre-Login Payload (aus Log rekonstruiert oder Standard)
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")
LBCS_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")

logger = logging.getLogger("CamClient")

def setup_logging(debug_mode):
    log_fmt = '[%(asctime)s.%(msecs)03d] %(message)s'
    date_fmt = '%H:%M:%S'
    logging.basicConfig(level=logging.DEBUG if debug_mode else logging.INFO, 
                        format=log_fmt, datefmt=date_fmt)

def hex_dump_str(data):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        text_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<47}  {text_part}")
    return "\n".join(lines)

def analyze_packet(data):
    if len(data) == 4 and data == b'\x00\x00\x00\x00': return "HEARTBEAT"
    if len(data) < 8 or data[0] != 0xF1:
        if data == b'\xf1\xe0\x00\x00': return "ERROR (0xE0) - Session/Auth Fail"
        if data == b'\xf1\xf0\x00\x00': return "FATAL (0xF0) - State Error"
        return f"UNKNOWN ({len(data)} bytes)"
    
    p_type = data[1]
    rudp_seq = data[7]
    base = f"RUDP(Type={p_type:02X}, Seq={rudp_seq})"
    
    if p_type == 0xD1:
        if len(data) >= 12: return f"{base} -> ACK(Seq {data[9]})"
        return f"{base} -> CONTROL"
    if p_type == 0xD0:
        if len(data) >= 11 and data[8:11] == b'ACK': return f"{base} -> TEXT ACK"
        if len(data) > 24 and data[8:15] == b'ARTEMIS':
            try:
                cmd = struct.unpack('<I', data[16:20])[0]
                seq = struct.unpack('<I', data[20:24])[0]
                return f"{base} -> ARTEMIS(Cmd={cmd}, AppSeq={seq})"
            except: pass
    return base

class WiFiWorker:
    @staticmethod
    def connect(ssid, password):
        try:
            if subprocess.run(["iwgetid", "-r"], capture_output=True, text=True).stdout.strip() == ssid: return True
        except: pass
        subprocess.run(["sudo", "nmcli", "c", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "d", "wifi", "rescan"], capture_output=True)
        time.sleep(3)
        res = subprocess.run(["sudo", "nmcli", "d", "wifi", "connect", ssid, "password", password, "ifname", "wlan0"], capture_output=True)
        subprocess.run(["sudo", "iwconfig", "wlan0", "power", "off"], check=False)
        return res.returncode == 0

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
        except Exception: return False

class HeartbeatThread(threading.Thread):
    def __init__(self, sock, target_ip, target_port):
        super().__init__()
        self.sock = sock
        self.target = (target_ip, target_port)
        self.running = True
        self.daemon = True

    def run(self):
        while self.running:
            try:
                # Heartbeat sendet 4 Null-Bytes
                self.sock.sendto(b'\x00\x00\x00\x00', self.target)
                time.sleep(2.0)
            except: pass
    
    def stop(self): self.running = False

class Session:
    def __init__(self, debug=False):
        self.sock = None
        self.active_port = 40611
        self.global_seq = 1 
        self.debug = debug
        self.token = None 

    def log_packet(self, direction, data, addr=None):
        if not self.debug: return
        desc = analyze_packet(data)
        logger.debug(f"{direction} {desc} ({len(data)} bytes)")
        if "ARTEMIS" in desc or "ERROR" in desc:
             logger.debug("\n" + hex_dump_str(data))

    def setup_network(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((TARGET_IP, 1)); local_ip = s.getsockname()[0]; s.close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((local_ip, FIXED_LOCAL_PORT))
            self.sock.settimeout(2.0) 
            logger.info(f"Socket gebunden an {local_ip}:{FIXED_LOCAL_PORT}")
            return True
        except: return False

    def next_seq(self):
        self.global_seq = (self.global_seq + 1) % 65535 # Größerer Bereich für Stabilität
        return self.global_seq

    def encrypt_json(self, obj):
        data = json.dumps(obj, separators=(',', ':')).encode('utf-8')
        data_with_null = data + b'\x00'
        pad_len = 16 - (len(data_with_null) % 16)
        if pad_len != 16: data_with_null += b'\x00' * pad_len
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        return cipher.encrypt(data_with_null)

    def decrypt_payload(self, data):
        try:
            if len(data) < 28: return None
            b64_part = data[28:].split(b'\x00')[0]
            raw_enc = base64.b64decode(b64_part)
            cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
            decrypted = cipher.decrypt(raw_enc)
            return json.loads(decrypted.decode('utf-8').rstrip('\x00'))
        except Exception: return None

    def send_cmd(self, cmd_id, payload):
        if self.token: payload["token"] = self.token
        enc_data = self.encrypt_json(payload)
        b64_body = base64.b64encode(enc_data) + b'\x00'
        curr_seq = self.next_seq()
        
        # ARTEMIS Header (20 Bytes)
        art_hdr = b'ARTEMIS\x00' + struct.pack('<III', cmd_id, curr_seq, len(b64_body))
        full_p = art_hdr + b64_body
        
        # RUDP Header (8 Bytes)
        blen = len(full_p) + 4
        rudp_hdr = struct.pack('>BBHBBBB', 0xF1, 0xD0, blen, 0xD1, 0x00, 0x00, curr_seq % 255)
        
        self.sock.sendto(rudp_hdr + full_p, (TARGET_IP, self.active_port))
        self.log_packet("📤 [TX]", rudp_hdr + full_p)
        return curr_seq

    def wait_for_data(self, timeout=5.0):
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = self.sock.recvfrom(4096)
                self.log_packet("📥 [RX]", data, addr)
                if len(data) > 8 and data[0] == 0xF1:
                    # Sende ACK für empfangene Datenpakete
                    if data[1] == 0xD0:
                        ack, _ = self.build_ack_packet(data[7])
                        self.sock.sendto(ack, addr)
                    
                    res = self.decrypt_payload(data)
                    if res: return res
            except socket.timeout: pass
        return None

    def build_ack_packet(self, seq):
        # Einfaches ACK für RUDP
        return struct.pack('>BBHBBBB', 0xF1, 0xD1, 4, 0xD1, 0x00, 0x00, seq), seq

    def run(self):
        if not self.setup_network(): return
        logger.info("Starte Discovery...")
        self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, 40611))
        time.sleep(0.5)

        # LOGIN (Cmd 2)
        logger.info("Sende APP LOGIN...")
        login_data = {
            "cmdId": 2, "usrName": "admin", "password": "admin",
            "utcTime": 1, "supportHeartBeat": True
        }
        self.send_cmd(2, login_data)
        
        resp = self.wait_for_data()
        if resp and 'token' in resp:
            self.token = resp['token']
            logger.info(f"✅ Login OK! Token: {self.token}")
            HeartbeatThread(self.sock, TARGET_IP, self.active_port).start()
        else:
            logger.error("❌ Login fehlgeschlagen."); return

        # DATEILISTE (Cmd 768)
        self.send_cmd(768, {"cmdId": 768, "itemCntPerPage": 10, "pageNo": 0})
        resp = self.wait_for_data()
        if resp and "mediaFiles" in resp:
            logger.info(f"✅ {len(resp['mediaFiles'])} Dateien gefunden.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kamera Thumbnail Downloader")
    # Flags korrekt als 'store_true' definieren
    parser.add_argument("--wifi", action="store_true", help="WiFi Verbindung herstellen")
    parser.add_argument("--ble", action="store_true", help="Kamera via BLE aufwecken")
    parser.add_argument("--debug", action="store_true", help="Detaillierte Debug-Logs anzeigen")
    
    args = parser.parse_args()
    setup_logging(args.debug)

    if os.geteuid() != 0:
        logger.warning("⚠️  NMCLI benötigt oft Root-Rechte. Bitte mit sudo starten!")

    if args.ble:
        logger.info("Starte BLE Wakeup Prozess...")
        asyncio.run(BLEWorker.wake_camera(BLE_MAC))
        logger.info("Warte 15s auf WLAN-Bereitschaft der Kamera...")
        time.sleep(15)

    if args.wifi:
        if not WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS):
            logger.error("❌ WiFi Verbindung fehlgeschlagen. Abbruch.")
            sys.exit(1)

    # Starte die Session
    Session(debug=args.debug).run()
