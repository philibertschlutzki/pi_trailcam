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
import binascii
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

ARTEMIS_HELLO = bytes.fromhex(
    "415254454d4953000200000001000000ad0000004a385757"
    "755144506d59534c66752f675841472b557162427935354b"
    "50326945323551504e6f667a6e3034302b4e493967377a65"
    "584c6b497058704330375358766f7372577363316d386d78"
    "6e7136684d694b776550624b4a5577765376715a62367330"
    "736c3173667a68335335307070307475324b657769305069"
    "4463765871584d3268506c4e6c6847536933465541762b50"
    "647935682f7278382b477437375468452b726431446d453d00"
)

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
                self.sock.sendto(HEARTBEAT_PAYLOAD, self.target)
                time.sleep(1.0)
            except: pass
    
    def stop(self): self.running = False

class Session:
    def __init__(self, debug=False):
        self.sock = None
        self.active_port = None
        self.global_seq = 0 
        self.app_seq = 1
        self.debug = debug
        self.token = None # NEU: Token Speicher

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

    def build_cmd_packet(self, encrypted_payload):
        b64_payload = base64.b64encode(encrypted_payload)
        self.app_seq += 1
        wrapper_header = b'ARTEMIS\x00' + struct.pack('<III', 2, self.app_seq, len(b64_payload) + 1)
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
                             if len(data) >= 11 and data[8:11] == b'ACK': return True
                             pass # Data content is handled later
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
                    ack_pkt, _ = self.build_packet(0xD1, bytearray([0x00, rx_seq, 0x00, rx_seq]))
                    self.send_raw(ack_pkt)

                    payload = data[8:]
                    if payload.startswith(b'ACK'): continue 
                    
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
        # NEU: Token im Download-Request (falls nötig, schadet nicht)
        req_json = { 
            "cmdId": 1285, 
            "downloadReqs": [{ "fileType": file_type, "dirNum": media_dir, "mediaNum": media_num }] 
        }
        if self.token: req_json["token"] = self.token # Token einfügen

        enc = self.encrypt_json(req_json)
        payload = self.build_cmd_packet(enc)
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
                    if data[4] == 0xD1: 
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

        logger.info("1. Login...")
        enc_login = self.encrypt_json({ "utcTime": int(time.time()), "nonce": os.urandom(8).hex() })
        full_login = PHASE2_STATIC_HEADER + enc_login
        
        if not self.send_reliable(0xF9, full_login, "Login"):
            logger.warning("Kein Login-ACK, versuche weiter...")
        
        hb.start()
        time.sleep(0.5)

        logger.info("2. Handshake...")
        self.send_reliable(0xD0, ARTEMIS_HELLO, "Hello")
        
        # --- NEU: TOKEN ABFRAGEN ---
        logger.info("⏳ Warte auf Token aus Hello-Antwort...")
        token_resp = self.wait_for_data(timeout=5.0)
        
        if token_resp:
            if 'token' in token_resp:
                self.token = token_resp['token']
            elif 'stationId' in token_resp:
                self.token = token_resp['stationId']
            
            if self.token:
                logger.info(f"✅ Token erhalten: {self.token}")
            else:
                logger.warning(f"⚠️ Antwort erhalten, aber kein Token: {token_resp}")
        else:
            logger.warning("⚠️ Keine Antwort auf Hello erhalten! Fortsetzung riskant...")
        # ---------------------------

        self.send_reliable(0xD0, MAGIC_BODY_1, "Magic1")
        time.sleep(0.05)
        self.send_reliable(0xD0, MAGIC_BODY_2, "Magic2")
        time.sleep(0.5)

        logger.info("3. Get Media List (Cmd 768)...")
        # --- NEU: TOKEN EINFÜGEN ---
        list_params = { "cmdId": 768, "itemCntPerPage": 10, "pageNo": 0 }
        if self.token: list_params["token"] = self.token
        
        enc_list = self.encrypt_json(list_params)
        payload = self.build_cmd_packet(enc_list)
        
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
