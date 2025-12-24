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
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")
LBCS_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")

# Magic Packets
MAGIC_BODY_1 = bytes.fromhex("000000000000") 
MAGIC_BODY_2 = bytes.fromhex("0000")         
HEARTBEAT_PAYLOAD = bytes.fromhex("00000000")

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
                # Sende nur, wenn Session aktiv (vermeidet 0xE0 Fehler vor Login)
                time.sleep(2.0)
            except: pass
    
    def stop(self): self.running = False

class Session:
    def __init__(self, debug=False):
        self.sock = None
        self.active_port = None
        self.global_seq = 0 
        self.app_seq = 1
        self.debug = debug
        self.token = None # Token Speicher

    def log_packet(self, direction, data, addr=None):
        if not self.debug: return
        if len(data) > 2 and data[1] == 0x42: return
        desc = analyze_packet(data)
        logger.debug(f"{direction} {desc} ({len(data)} bytes)")
        if "ARTEMIS" in desc or "Login" in desc or "UNKNOWN" in desc or "ERROR" in desc:
             logger.debug("\n" + hex_dump_str(data))

    def setup_network(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((TARGET_IP, 1)); local_ip = s.getsockname()[0]; s.close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((local_ip, FIXED_LOCAL_PORT))
            self.sock.settimeout(1.0) 
            logger.info(f"Socket gebunden an {local_ip}:{FIXED_LOCAL_PORT}")
            return True
        except: return False

    def next_seq(self):
        self.global_seq = (self.global_seq + 1) % 255
        if self.global_seq == 0: self.global_seq = 1
        return self.global_seq

    def encrypt_json(self, json_obj):
        json_str = json.dumps(json_obj, separators=(',', ':'))
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        return cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))

    def decrypt_bytes(self, encrypted_data):
        try:
            cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            return json.loads(decrypted.decode('utf-8').rstrip('\x00'))
        except: return None

    def build_packet(self, p_type, payload):
        seq = self.next_seq()
        bl = len(payload) + 4
        return bytearray([0xF1, p_type, (bl >> 8) & 0xFF, bl & 0xFF, 0xD1, 0x00, 0x00, seq]) + payload, seq

    # FIX: cmd_id Parameter hinzugefügt, um Cmd 0 (Login) senden zu können
    def build_cmd_packet(self, encrypted_payload, cmd_id=2):
        b64_payload = base64.b64encode(encrypted_payload)
        self.app_seq += 1
        # ARTEMIS Header: ARTEMIS + CmdID (4) + AppSeq (4) + Len (4)
        wrapper_header = b'ARTEMIS\x00' + struct.pack('<III', cmd_id, self.app_seq, len(b64_payload) + 1)
        return wrapper_header + b64_payload + b'\x00'

    def build_batch_ack(self, seq_list):
        count = len(seq_list)
        payload = bytearray([(count >> 8) & 0xFF, count & 0xFF])
        for s in seq_list: payload.extend([(s >> 8) & 0xFF, s & 0xFF])
        bl = len(payload) + 4
        return bytearray([0xF1, 0xD1, (bl >> 8) & 0xFF, bl & 0xFF, 0xD1, 0x04, 0x00, 0x00]) + payload

    def send_raw(self, pkt):
        self.log_packet("📤 [TX]", pkt)
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))

    def send_reliable(self, p_type, payload, label="Packet"):
        pkt, seq = self.build_packet(p_type, payload)
        if isinstance(payload, bytes) and len(payload) > 8 and payload[0] == 0xF1:
            pkt = payload; seq = pkt[7]

        logger.info(f"Sende {label} (Seq {seq})...")
        for attempt in range(5): 
            self.send_raw(pkt)
            start_wait = time.time()
            while time.time() - start_wait < 0.4:
                try:
                    data, addr = self.sock.recvfrom(4096)
                    self.log_packet("📥 [RX]", data, addr)
                    if len(data) > 8 and data[0] == 0xF1:
                        if data[1] == 0xD1: # Protocol ACK
                            if (len(data) >= 10 and data[9] == seq) or data[7] == seq: return True
                        elif data[1] == 0xD0: # Text ACK or Data
                             # Wir nehmen Data auch als ACK an
                             return True
                except socket.timeout: pass
                except Exception: pass
        logger.warning(f"❌ Kein ACK für {label} (Seq {seq})")
        return False

    def wait_for_data(self, timeout=8.0):
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = self.sock.recvfrom(4096)
                self.log_packet("📥 [RX]", data, addr)
                
                if len(data) > 8 and data[0] == 0xF1 and data[1] == 0xD0:
                    rx_seq = data[7]
                    # IMMER ACK senden
                    ack_pkt, _ = self.build_packet(0xD1, bytearray([0x00, rx_seq, 0x00, rx_seq]))
                    self.send_raw(ack_pkt)

                    payload = data[8:]
                    if payload.startswith(b'ACK'): continue 
                    
                    # Decrypt Logic
                    if b'ARTEMIS' in payload and len(payload) > 20:
                        b64_data = payload[20:].rstrip(b'\x00')
                        try:
                            res = self.decrypt_bytes(base64.b64decode(b64_data))
                            if res: return res
                        except: pass
                    
                    try:
                        res = self.decrypt_bytes(base64.b64decode(payload.rstrip(b'\x00')))
                        if res: return res
                    except: pass
            except socket.timeout: pass
        return None

    def download_file(self, file_type, media_dir, media_num):
        logger.info(f"Starte Download: Dir={media_dir}, Num={media_num}")
        req_json = { "cmdId": 1285, "downloadReqs": [{ "fileType": file_type, "dirNum": media_dir, "mediaNum": media_num }] }
        if self.token: req_json["token"] = self.token # Token einfügen

        enc = self.encrypt_json(req_json)
        payload = self.build_cmd_packet(enc, 1285)
        pkt, _ = self.build_packet(0xD0, payload)
        self.send_raw(pkt) 
        
        received_chunks = {} 
        batch_seqs = []
        last_batch_time = time.time()
        
        while True:
            try:
                self.sock.settimeout(3.0)
                data, addr = self.sock.recvfrom(4096)
                if self.debug and len(received_chunks) % 20 == 0: self.log_packet("📥 [RX]", data, addr)

                if len(data) > 8 and data[0] == 0xF1 and data[1] == 0xD0:
                    if data[4] == 0xD1: # Bulk Header
                        seq_16 = (data[6] << 8) | data[7]
                        if seq_16 not in received_chunks:
                            received_chunks[seq_16] = data[8:]
                            batch_seqs.append(seq_16)
                        if len(batch_seqs) >= 20 or (time.time() - last_batch_time > 0.1 and len(batch_seqs) > 0):
                            self.send_raw(self.build_batch_ack(batch_seqs))
                            batch_seqs = []
                            last_batch_time = time.time()
                            sys.stdout.write(f"\rChunks: {len(received_chunks)}")
                            sys.stdout.flush()
            except socket.timeout: break
            except KeyboardInterrupt: break
            
        if received_chunks:
            filename = f"download_{media_dir}_{media_num}.jpg"
            with open(filename, "wb") as f:
                for seq in sorted(received_chunks.keys()): f.write(received_chunks[seq])
            logger.info(f"\n✅ Datei {filename} gespeichert!")
        else: logger.warning("\nKein Download.")

    def run(self):
        if not self.setup_network(): return
        logger.info("Starte Discovery...")
        for p in TARGET_PORTS: self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, p))
        start = time.time()
        while time.time() - start < 1.5:
            try:
                data, addr = self.sock.recvfrom(1024)
                if len(data) > 4 and data[0] == 0xF1:
                    self.active_port = addr[1]; logger.info(f"Target Port: {self.active_port}"); break
            except: pass
        if not self.active_port: logger.error("Discovery Failed."); return

        hb = HeartbeatThread(self.sock, TARGET_IP, self.active_port)

        # 1. Pre-Login (F9)
        logger.info("1. Sende Pre-Login (F9)...")
        plain_login = json.dumps({ "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }, separators=(',', ':')).encode('utf-8')
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        enc_login = PHASE2_STATIC_HEADER + cipher.encrypt(pad(plain_login, AES.block_size))
        
        # F9 Paket manuell bauen
        pkt_len = len(enc_login) + 4
        header = struct.pack('>BBH', 0xF1, 0xF9, pkt_len)
        trailer = struct.pack('BBBB', 0xD1, 0x00, 0x00, self.next_seq())
        full_login_pkt = header + trailer + enc_login
        
        if not self.send_reliable(0xF9, full_login_pkt, "Pre-Login"):
            logger.warning("Kein Pre-Login ACK, versuche weiter...")
        
        # 2. Login Cmd 0 (Ersetzt Hello)
        logger.info("2. Sende APP LOGIN (Cmd 0)...")
        login_data = {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "needAudio": 0,
            "utcTime": int(time.time()),
            "supportHeartBeat": True
        }
        enc_app_login = self.encrypt_json(login_data)
        # build_cmd_packet nutzt jetzt den neuen Parameter cmd_id=0
        payload = self.build_cmd_packet(enc_app_login, cmd_id=0)
        
        if self.send_reliable(0xD0, payload, "Login Cmd 0"):
            logger.info("Warte auf Token...")
            resp = self.wait_for_data(timeout=5.0)
            if resp:
                if 'token' in resp:
                    self.token = resp['token']
                    logger.info(f"✅ LOGIN ERFOLGREICH! Token: {self.token}")
                elif 'stationId' in resp:
                    self.token = resp['stationId']
                    logger.info(f"✅ LOGIN ERFOLGREICH! StationId: {self.token}")
                
                # Heartbeat jetzt sicher starten
                hb.start()
            else:
                logger.error("❌ Keine Login-Antwort empfangen. Abbruch.")
                return 
        else:
            logger.error("❌ Senden von Login Cmd 0 fehlgeschlagen.")
            return

        time.sleep(0.5)

        # 3. Magic / GetDevInfo
        logger.info("3. Get Dev Info (Cmd 512)...")
        dev_info_req = { "cmdId": 512 }
        if self.token: dev_info_req["token"] = self.token
        enc_dev = self.encrypt_json(dev_info_req)
        payload = self.build_cmd_packet(enc_dev, 512)
        if self.send_reliable(0xD0, payload, "GetDevInfo"):
             resp = self.wait_for_data(timeout=3.0)
             if resp: logger.info(f"Geräteinfo: {resp.get('fwVerName', 'Unknown')}")

        time.sleep(0.5)

        # 4. Get Media List
        logger.info("4. Get Media List (Cmd 768)...")
        list_req = { "cmdId": 768, "itemCntPerPage": 10, "pageNo": 0 }
        if self.token: list_req["token"] = self.token

        enc_list = self.encrypt_json(list_req)
        payload = self.build_cmd_packet(enc_list, 768)
        
        if self.send_reliable(0xD0, payload, "GetMediaList"): 
             logger.info("Warte auf Dateiliste...")
             resp = self.wait_for_data(timeout=10.0)
             if resp and "mediaFiles" in resp:
                 files = resp["mediaFiles"]
                 logger.info(f"✅ {len(files)} Dateien gefunden.")
                 if len(files) > 0:
                     tf = files[-1]
                     self.download_file(tf.get("fileType", 0), tf.get("mediaDirNum", 0), tf.get("mediaNum", 0))
             else: logger.error("❌ Keine Dateiliste empfangen.")
        hb.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wifi", action="store_true")
    parser.add_argument("--ble", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    setup_logging(args.debug)
    if os.geteuid() != 0: logger.warning("⚠️  Bitte als root starten!")
    if args.ble: asyncio.run(BLEWorker.wake_camera(BLE_MAC)); time.sleep(20)
    if args.wifi: WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS)
    Session(debug=args.debug).run()
