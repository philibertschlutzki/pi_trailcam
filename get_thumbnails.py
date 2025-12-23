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
from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

# --- CONFIG ---
TARGET_IP = "192.168.43.1"
TARGET_PORTS = [40611, 3333]
FIXED_LOCAL_PORT = 35281

DEFAULT_SSID = "KJK_E0FF"
DEFAULT_PASS = "85087127"
BLE_MAC = "C6:1E:0D:E0:32:E8"

# --- CRYPTO CONSTANTS ---
PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

# --- PAYLOADS ---
LBCS_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")

# ARTEMIS Hello Body
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

# Magic Handshake Bodies (Null-Payloads)
MAGIC_BODY_1 = bytes.fromhex("000000000000") 
MAGIC_BODY_2 = bytes.fromhex("0000")         

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("CamClient")

# --- HELPER CLASSES ---
class SystemTweaks:
    @staticmethod
    def disable_wifi_powersave():
        try:
            subprocess.run(["sudo", "iwconfig", "wlan0", "power", "off"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    def stop(self):
        self.running = False

class BLEWorker:
    @staticmethod
    async def wake_camera(mac):
        logger.info(f"Suche BLE {mac}...")
        try:
            dev = await BleakScanner.find_device_by_address(mac, timeout=20.0)
            if not dev: return False
            async with BleakClient(dev, timeout=10.0) as client:
                await client.write_gatt_char("00000002-0000-1000-8000-00805f9b34fb", 
                                             bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]), 
                                             response=True)
                return True
        except Exception: return False

class WiFiWorker:
    @staticmethod
    def connect(ssid, password):
        SystemTweaks.disable_wifi_powersave()
        try:
            iw_out = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True).stdout.strip()
            if iw_out == ssid: return True
        except: pass
        subprocess.run(["sudo", "nmcli", "c", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "d", "wifi", "rescan"], capture_output=True)
        time.sleep(3)
        res = subprocess.run(["sudo", "nmcli", "d", "wifi", "connect", ssid, "password", password, "ifname", "wlan0"], capture_output=True)
        SystemTweaks.disable_wifi_powersave()
        return res.returncode == 0

# --- PROTOCOL HANDLER ---

class Session:
    def __init__(self):
        self.sock = None
        self.active_port = None
        self.running = True
        self.global_seq = 0 

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
        self.sock.settimeout(3.0) # Timeout auf 3s erhöht
        logger.info(f"Socket gebunden an {local_ip}:{FIXED_LOCAL_PORT}")
        return True

    def next_seq(self):
        self.global_seq = (self.global_seq + 1) % 255
        if self.global_seq == 0: self.global_seq = 1
        return self.global_seq

    def encrypt_json(self, json_obj):
        # JSON String erstellen
        json_str = json.dumps(json_obj, separators=(',', ':'))
        # AES ECB Encrypt mit Padding
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))
        return encrypted

    def decrypt_payload(self, encrypted_data):
        try:
            cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            # Remove Trash Bytes at the end if any
            return json.loads(decrypted.decode('utf-8').rstrip('\x00'))
        except Exception as e:
            # Nur loggen, wenn es wirklich JSON sein sollte, um Spam zu vermeiden
            # logger.debug(f"Decryption Error (might be not JSON): {e}")
            return None

    def build_rudp_packet(self, packet_type, payload):
        seq = self.next_seq()
        body_len = len(payload) + 4 
        # RUDP Header: F1 [Type] [LenH] [LenL] D1 00 00 [Seq]
        header = bytearray([0xF1, packet_type, (body_len >> 8) & 0xFF, body_len & 0xFF, 
                            0xD1, 0x00, 0x00, seq])
        return header + payload, seq

    def build_cmd_packet(self, cmd_type, encrypted_payload):
        # Artemis Command Wrapper
        # Header: ARTEMIS\0 [CmdType 4 Bytes] [Len 4 Bytes] [Payload]
        # CmdType: 2 = Request
        wrapper_header = b'ARTEMIS\x00' + struct.pack('<II', 2, len(encrypted_payload))
        full_body = wrapper_header + encrypted_payload
        return self.build_rudp_packet(0xD0, full_body)

    def build_batch_ack(self, seq_list):
        count = len(seq_list)
        payload = bytearray()
        payload.append((count >> 8) & 0xFF)
        payload.append(count & 0xFF)
        for s in seq_list:
            payload.append((s >> 8) & 0xFF)
            payload.append(s & 0xFF)
        body_len = len(payload) + 4
        header = bytearray([0xF1, 0xD1, (body_len >> 8) & 0xFF, body_len & 0xFF, 
                            0xD1, 0x04, 0x00, 0x00])
        return header + payload

    def send_raw(self, data):
        self.sock.sendto(data, (TARGET_IP, self.active_port))

    def discover_and_login(self):
        logger.info("Starte Discovery...")
        for p in TARGET_PORTS:
            self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, p))
        
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

        logger.info("Sende Login (Crypto)...")
        payload = { "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }
        enc = self.encrypt_json(payload)
        pkt = struct.pack('>BBH', 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + enc)) + PHASE2_STATIC_HEADER + enc
        self.send_raw(pkt)
        time.sleep(0.2)
        return True

    def get_file_list(self):
        req_json = {
            "cmdId": 768,           # EC_CMD_ID_GET_MEDIA_LIST
            "itemCntPerPage": 10,
            "pageNo": 0
        }
        logger.info(f"Frage Dateiliste ab: {req_json}")
        
        enc_payload = self.encrypt_json(req_json)
        pkt, _ = self.build_cmd_packet(0xD0, enc_payload)
        self.send_raw(pkt)

        # Antwort empfangen
        start = time.time()
        
        while time.time() - start < 5.0:
            try:
                data, _ = self.sock.recvfrom(4096)
                if len(data) > 8 and data[0] == 0xF1 and data[1] == 0xD0:
                    payload = data[8:]
                    
                    # DEBUG: Hexdump der empfangenen Daten
                    logger.info(f"Empfange {len(payload)} Bytes: {binascii.hexlify(payload[:30]).decode()}...")

                    # STRATEGIE 1: Payload enthält "ARTEMIS" Header
                    if b'ARTEMIS' in payload:
                        if len(payload) > 16:
                            encrypted_part = payload[16:]
                            res = self.decrypt_payload(encrypted_part)
                            if res: return res

                    # STRATEGIE 2: Payload ist direkt verschlüsseltes JSON (siehe Log Source 626)
                    # Versuche direkt zu entschlüsseln
                    res = self.decrypt_payload(payload)
                    if res: 
                        logger.info("✅ Entschlüsselung erfolgreich (Direkt)!")
                        return res
                    
            except socket.timeout: pass
            except Exception as e:
                logger.error(f"Fehler im Empfangsloop: {e}")
                
        return None

    def download_file(self, file_type, media_dir, media_num):
        logger.info(f"Starte Download für Dir: {media_dir}, Num: {media_num}...")
        
        req_json = {
            "cmdId": 1285,          # EC_CMD_ID_START_FILE_DOWNLOAD
            "downloadReqs": [
                {
                    "fileType": file_type,
                    "dirNum": media_dir,
                    "mediaNum": media_num
                }
            ]
        }
        
        logger.info(f"Sende Request: {req_json}")
        enc_payload = self.encrypt_json(req_json)
        pkt, _ = self.build_cmd_packet(0xD0, enc_payload)
        self.send_raw(pkt)
        
        received_chunks = {} 
        batch_seqs = []
        last_batch_time = time.time()
        start_wait = time.time()
        
        total_chunks_expected = 0
        
        while True:
            try:
                self.sock.settimeout(2.0)
                data, _ = self.sock.recvfrom(4096)
                
                if len(data) > 8 and data[0] == 0xF1:
                    if data[1] == 0xD0: # DATA Packet
                        # Check for Bulk Header (Byte 4 is D1, but Byte 5 is 00)
                        # Log Analysis: f1 d0 [len] [len] d1 00 [seq_h] [seq_l]
                        if data[4] == 0xD1:
                            seq_16 = (data[6] << 8) | data[7]
                            payload = data[8:]
                            
                            if seq_16 not in received_chunks:
                                received_chunks[seq_16] = payload
                                batch_seqs.append(seq_16)
                            
                            if len(batch_seqs) >= 20 or (time.time() - last_batch_time > 0.1 and len(batch_seqs) > 0):
                                ack_pkt = self.build_batch_ack(batch_seqs)
                                self.send_raw(ack_pkt)
                                batch_seqs = []
                                last_batch_time = time.time()
                                sys.stdout.write(f"\rChunks: {len(received_chunks)}")
                                sys.stdout.flush()
            
            except socket.timeout:
                if len(received_chunks) > 0:
                    logger.info("\nDownload Timeout (Fertig).")
                    break
                else:
                    if time.time() - start_wait > 5.0:
                        logger.warning("\nKeine Daten empfangen.")
                        break
            except KeyboardInterrupt: break
            
        if received_chunks:
            filename = f"download_{media_dir}_{media_num}.jpg"
            with open(filename, "wb") as f:
                for seq in sorted(received_chunks.keys()):
                    f.write(received_chunks[seq])
            logger.info(f"✅ Datei {filename} gespeichert!")
        else:
            logger.warning("Kein Download erfolgt.")

    def run(self):
        ping_thread = None
        try:
            if self.setup_network():
                ping_thread = NetworkPinger(TARGET_IP)
                ping_thread.start()

                if self.discover_and_login():
                    logger.info(">>> Handshake...")
                    pkt, _ = self.build_rudp_packet(0xD0, ARTEMIS_HELLO_BODY)
                    self.send_raw(pkt)
                    time.sleep(0.1)
                    
                    # Magic Packets (wichtig für State Machine der Kamera)
                    pkt, _ = self.build_rudp_packet(0xD1, MAGIC_BODY_1)
                    self.send_raw(pkt)
                    time.sleep(0.05)
                    pkt, _ = self.build_rudp_packet(0xD1, MAGIC_BODY_2)
                    self.send_raw(pkt)
                    time.sleep(0.5)
                    
                    # 1. Dateiliste holen
                    file_list_resp = self.get_file_list()
                    
                    if file_list_resp and "mediaFiles" in file_list_resp:
                        files = file_list_resp["mediaFiles"]
                        logger.info(f"Gefunden: {len(files)} Dateien.")
                        
                        if len(files) > 0:
                            target_file = files[-1] # Neuestes Bild
                            logger.info(f"Wähle Datei: {target_file}")
                            
                            m_type = target_file.get("fileType", 0) 
                            m_dir = target_file.get("mediaDirNum", 0)
                            m_num = target_file.get("mediaNum", 0)
                            
                            # 2. Download starten
                            self.download_file(m_type, m_dir, m_num)
                        else:
                            logger.warning("Keine Dateien auf der Kamera.")
                    else:
                        logger.error("Konnte Dateiliste nicht abrufen oder entschlüsseln.")
                        logger.error(f"Raw Response: {file_list_resp}")

                else: logger.error("❌ Discovery Failed.")
        except KeyboardInterrupt:
            logger.info("Abbruch.")
        finally:
            self.running = False
            if ping_thread: ping_thread.stop()
            if self.sock: self.sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wifi", action="store_true")
    parser.add_argument("--ble", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        logger.warning("⚠️  Bitte als root starten!")

    if args.ble:
        asyncio.run(BLEWorker.wake_camera(BLE_MAC))
        time.sleep(20)

    if args.wifi:
        WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS)

    Session().run()
