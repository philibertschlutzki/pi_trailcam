import socket
import struct
import time
import json
import logging
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- CONFIG ---
TARGET_IP = "192.168.43.1"
TARGET_PORT = 40611
PHASE2_KEY = b"a01bc23ed45fF56A"
# Statischer Header aus Frida-Log
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("CamClient")

class ArtemisSession:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)
        self.seq = 1
        self.token = None

    def encrypt_json(self, obj):
        # Kompaktes JSON ohne Leerzeichen
        data = json.dumps(obj, separators=(',', ':')).encode('utf-8')
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        return cipher.encrypt(pad(data, 16))

    def decrypt_payload(self, raw_b64):
        try:
            cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
            dec = unpad(cipher.decrypt(base64.b64decode(raw_b64)), 16)
            return json.loads(dec.decode('utf-8'))
        except: return None

    def send_cmd(self, cmd_id, payload_dict):
        # Falls ein Token existiert, muss er rein
        if self.token: payload_dict["token"] = self.token
        
        enc_data = self.encrypt_json(payload_dict)
        b64_body = base64.b64encode(enc_data) + b'\x00'
        
        # ARTEMIS Header bauen
        # ARTEMIS\0 + CmdID(4) + Seq(4) + Len(4)
        artemis_hdr = b'ARTEMIS\x00' + struct.pack('<III', cmd_id, self.seq, len(b64_body))
        full_payload = artemis_hdr + b64_body
        
        # RUDP Header
        blen = len(full_payload) + 4
        rudp_hdr = struct.pack('>BBHBBBB', 0xF1, 0xD0, blen, 0xD1, 0x00, 0x00, self.seq)
        
        logger.info(f"📤 Sende Cmd {cmd_id} (Seq {self.seq})")
        self.sock.sendto(rudp_hdr + full_payload, (TARGET_IP, TARGET_PORT))
        self.seq += 1

    def run(self):
        # 1. Login (Cmd 0 laut JSON Log)
        login_data = {
            "cmdId": 0, "usrName": "admin", "password": "admin",
            "utcTime": int(time.time()), "supportHeartBeat": True
        }
        self.send_cmd(0, login_data)
        
        try:
            data, _ = self.sock.recvfrom(2048)
            # Suche nach Base64 Payload im Paket
            if b'ARTEMIS' in data:
                resp = self.decrypt_payload(data[28:].split(b'\x00')[0])
                if resp and 'token' in resp:
                    self.token = resp['token']
                    logger.info(f"✅ Login Erfolg! Token: {self.token}")
                else:
                    logger.error("❌ Login erfolgreich, aber kein Token erhalten.")
                    return
        except:
            logger.error("❌ Timeout beim Login."); return

        # 2. Get Device Info (Cmd 512)
        self.send_cmd(512, {"cmdId": 512})
        try:
            data, _ = self.sock.recvfrom(2048)
            info = self.decrypt_payload(data[28:].split(b'\x00')[0])
            if info: logger.info(f"📸 Kamera: {info.get('modelName')} (FW: {info.get('fwVerName')})")
        except: pass

if __name__ == "__main__":
    ArtemisSession().run()
