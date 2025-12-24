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
TARGET_PORTS = [40611]
FIXED_LOCAL_PORT = 35281

DEFAULT_SSID = "KJK_E0FF"
DEFAULT_PASS = "85087127"
BLE_MAC = "C6:1E:0D:E0:32:E8"

# --- CRYPTO & CONSTANTS ---
# Verifiziert aus JADX: AESTool.DEFAULT_ENCRYPT_KEY
PHASE2_KEY = b"a01bc23ed45fF56A" 
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
        return f"UNKNOWN ({len(data)} bytes)"
    
    p_type = data[1]
    rudp_seq = data[7]
    base = f"RUDP(Type={p_type:02X}, Seq={rudp_seq})"
    
    if p_type == 0xD0:
        if len(data) > 24 and data[8:15] == b'ARTEMIS':
            try:
                cmd = struct.unpack('<I', data[16:20])[0]
                return f"{base} -> ARTEMIS(Cmd={cmd})"
            except: pass
    return base

class HeartbeatThread(threading.Thread):
    def __init__(self, session):
        super().__init__()
        self.session = session
        self.running = True
        self.daemon = True

    def run(self):
        while self.running:
            try:
                # App sendet alle 3 Sek Heartbeat (Cmd 525)
                if self.session.token:
                    self.session.send_cmd(525, {"cmdId": 525})
                time.sleep(3.0)
            except: pass
    
    def stop(self): self.running = False

class Session:
    def __init__(self, debug=False):
        self.sock = None
        self.active_port = None
        # JADX verifiziert: SeqManager nutzt einen einfachen globalen Counter
        self.seq = 1 
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
            self.sock.settimeout(1.5) 
            logger.info(f"Socket gebunden an {local_ip}:{FIXED_LOCAL_PORT}")
            return True
        except: return False

    def next_seq(self):
        curr = self.seq
        self.seq = (self.seq + 1) % 65535
        return curr

    def encrypt_json(self, json_obj):
        # separators=(',', ':') für kompaktes Java-Stil JSON
        json_str = json.dumps(json_obj, separators=(',', ':'))
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        # Empfehlung: PKCS7 (16) ist Standard in AESTool.java
        return cipher.encrypt(pad(json_str.encode('utf-8'), 16))

    def decrypt_payload(self, data):
        try:
            # Empfehlung: Offset 28 überspringt RUDP (8) + ARTEMIS Header (20)
            payload = data[28:].split(b'\x00')[0]
            raw_enc = base64.b64decode(payload)
            cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
            dec = unpad(cipher.decrypt(raw_enc), 16)
            return json.loads(dec.decode('utf-8'))
        except: return None

    def send_cmd(self, cmd_id, payload_dict):
        # JADX Log-Analyse: Token MUSS in jedes Paket nach Login
        if self.token:
            payload_dict["token"] = self.token
        
        enc_data = self.encrypt_json(payload_dict)
        b64_body = base64.b64encode(enc_data) + b'\x00'
        
        # ARTEMIS Header: "ARTEMIS\x00" (8) + Cmd(4) + Seq(4) + Len(4)
        s = self.next_seq()
        art_hdr = b'ARTEMIS\x00' + struct.pack('<III', cmd_id, s, len(b64_body))
        full_p = art_hdr + b64_body
        
        # RUDP Header: F1 + Type(D0) + Len + D1 + 00 + 00 + Seq
        rudp_hdr = struct.pack('>BBHBBBB', 0xF1, 0xD0, len(full_p)+4, 0xD1, 0x00, 0x00, s % 255)
        
        pkt = rudp_hdr + full_p
        self.log_packet("📤 [TX]", pkt)
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))
        return s

    def run(self):
        if not self.setup_network(): return
        logger.info("Starte Discovery...")
        for p in [40611, 3333]: self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, p))
        try:
            data, addr = self.sock.recvfrom(1024)
            self.active_port = addr[1]; logger.info(f"Target Port: {self.active_port}")
        except: logger.error("Discovery Failed."); return

        # 1. Pre-Login (F9)
        logger.info("1. Sende Pre-Login (F9)...")
        pre_json = {"utcTime": int(time.time()), "nonce": os.urandom(8).hex()}
        enc_pre = self.encrypt_json(pre_json)
        full_payload = PHASE2_STATIC_HEADER + enc_pre
        pkt_len = len(full_payload) + 4
        f9_hdr = struct.pack('>BBHBBBB', 0xF1, 0xF9, pkt_len, 0xD1, 0x00, 0x00, 1)
        self.sock.sendto(f9_hdr + full_payload, (TARGET_IP, self.active_port))
        time.sleep(0.3)

        # 2. Login (Cmd 0)
        logger.info("2. Sende Login (Cmd 0)...")
        login_json = {
            "cmdId": 0, "usrName": "admin", "password": "admin",
            "utcTime": int(time.time()), "supportHeartBeat": True
        }
        self.send_cmd(0, login_json)
        
        try:
            data, _ = self.sock.recvfrom(2048)
            resp = self.decrypt_payload(data)
            if resp and 'token' in resp:
                self.token = resp['token']
                logger.info(f"✅ Login Erfolg! Token: {self.token}")
                HeartbeatThread(self).start()
            else:
                logger.error("❌ Login fehlgeschlagen oder kein Token erhalten."); return
        except: logger.error("❌ Timeout beim Login."); return

        # 3. Get Device Info (Cmd 512)
        logger.info("3. Hole Geräteinfo...")
        self.send_cmd(512, {"cmdId": 512})
        try:
            data, _ = self.sock.recvfrom(2048)
            info = self.decrypt_payload(data)
            if info: logger.info(f"Kamera: {info.get('modelName')} (Batterie: {info.get('batPercent')}%)")
        except: pass

        # 4. Get Media List (Cmd 768)
        logger.info("4. Hole Dateiliste...")
        self.send_cmd(768, {"cmdId": 768, "itemCntPerPage": 10, "pageNo": 0})
        try:
            data, _ = self.sock.recvfrom(4096)
            resp = self.decrypt_payload(data)
            if resp and "mediaFiles" in resp:
                logger.info(f"✅ {len(resp['mediaFiles'])} Dateien auf der Kamera gefunden.")
        except: logger.error("❌ Fehler beim Empfang der Dateiliste.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    setup_logging(args.debug)
    Session(debug=args.debug).run()
