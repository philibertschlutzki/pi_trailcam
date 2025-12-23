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

# GET PICTURE COMMAND (from Log Source 56)
# Command ID: 0x02, Payload starts with J8WW...
CMD_GET_PICTURE = bytes.fromhex(
    "415254454d495300"
    "020000001b000000ad0000004a385757"
    "755144506d59534c66752f675841472b"
    "557162427935354b5032694532355150"
    "4e6f667a6e3034302b4e493967377a65"
    "584c6b497058704330375358766f7372"
    "577363316d386d786e7136684d694b77"
    "6550624b4a5577765376715a62367330"
    "736c3173667a685678794f3770656c79"
    "49396365707a38624c7274534c515a6a"
    "756d4334476136785550533059707a76"
    "4b426d2b2f38646f595a4b4e39375268"
    "30706b465859553d00"
)

# Magic Handshake Bodies (Null-Payloads)
MAGIC_BODY_1 = bytes.fromhex("000000000000") 
MAGIC_BODY_2 = bytes.fromhex("0000")         

# Crypto
PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("CamClient")

# --- HELPER CLASSES (Unchanged) ---
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

# --- SESSION ---

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
        self.sock.settimeout(1.0) 
        logger.info(f"Socket gebunden an {local_ip}:{FIXED_LOCAL_PORT}")
        return True

    def next_seq(self):
        self.global_seq = (self.global_seq + 1) % 255
        if self.global_seq == 0: self.global_seq = 1
        return self.global_seq

    def build_rudp_packet(self, packet_type, payload):
        seq = self.next_seq()
        body_len = len(payload) + 4 
        header = bytearray([0xF1, packet_type, (body_len >> 8) & 0xFF, body_len & 0xFF, 
                            0xD1, 0x00, 0x00, seq])
        return header + payload, seq

    def build_batch_ack(self, seq_list):
        # Constructs the special "Bulk/Batch ACK" found in the log
        # Header: F1 D1 [LEN] [LEN] D1 04 [COUNT_H] [COUNT_L] [SEQ1_H] [SEQ1_L] ...
        
        count = len(seq_list)
        payload = bytearray()
        payload.append((count >> 8) & 0xFF)
        payload.append(count & 0xFF)
        
        for s in seq_list:
            payload.append((s >> 8) & 0xFF)
            payload.append(s & 0xFF)
            
        body_len = len(payload) + 4
        # Note: Subtype is 0x04 here!
        header = bytearray([0xF1, 0xD1, (body_len >> 8) & 0xFF, body_len & 0xFF, 
                            0xD1, 0x04, 0x00, 0x00]) # Seq bytes seem unused/0 in header for batch ack
        return header + payload

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
        enc = AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(pad(json.dumps(payload, separators=(',', ':')).encode(), AES.block_size))
        pkt = struct.pack('>BBH', 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + enc)) + PHASE2_STATIC_HEADER + enc
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))
        time.sleep(0.2)
        return True

    def simple_send(self, payload, packet_type=0xD0):
        pkt, seq = self.build_rudp_packet(packet_type, payload)
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))
        return seq

    def download_loop(self):
        logger.info(">>> Starte Download Loop (Bulk Mode)...")
        
        # Sequenznummern sind hier 16-Bit (2 Bytes)!
        received_chunks = {} # seq -> data
        batch_seqs = []
        last_batch_time = time.time()
        
        total_bytes = 0
        
        while True:
            try:
                data, _ = self.sock.recvfrom(4096)
                if len(data) > 8 and data[0] == 0xF1:
                    
                    # Normal STOP-AND-WAIT Packet (Handshake/Control)
                    if data[1] == 0xD0 and data[5] == 0x00:
                        # Behandle wie bisher (ACK senden)
                        rx_seq = data[7]
                        ack_payload = bytearray([0x00, rx_seq, 0x00, rx_seq])
                        pkt, _ = self.build_rudp_packet(0xD1, ack_payload) # nutzt build_rudp_packet intern
                        # Hack: wir müssen das Paket manuell bauen, da build_rudp_packet seq erhöht
                        # Einfachheitshalber: Sende Standard ACK
                        ack_header = bytearray([0xF1, 0xD1, 0x00, 0x08, 0xD1, 0x00, 0x00, rx_seq])
                        self.sock.sendto(ack_header + ack_payload, (TARGET_IP, self.active_port))
                        
                        # Prüfen ob Download fertig? (Log source 536/545)
                        if b"ARTEMIS" in data:
                            logger.info("Empfange Steuerdaten (ARTEMIS) im Download-Loop.")
                    
                    # BULK DATA PACKET
                    # Format: F1 D0 [LEN] [LEN] D1 00 [SEQ_H] [SEQ_L] [DATA...]
                    elif data[1] == 0xD0: 
                        # Extract 16-bit Sequence
                        seq_16 = (data[6] << 8) | data[7]
                        payload = data[8:]
                        
                        if seq_16 not in received_chunks:
                            received_chunks[seq_16] = payload
                            batch_seqs.append(seq_16)
                            total_bytes += len(payload)
                        
                        # Sende Batch ACK wenn wir genug gesammelt haben oder Zeit vergangen ist
                        if len(batch_seqs) >= 20 or (time.time() - last_batch_time > 0.1 and len(batch_seqs) > 0):
                            ack_pkt = self.build_batch_ack(batch_seqs)
                            self.sock.sendto(ack_pkt, (TARGET_IP, self.active_port))
                            logger.info(f"Sende Batch ACK für {len(batch_seqs)} Pakete. Total: {total_bytes} bytes")
                            batch_seqs = []
                            last_batch_time = time.time()

            except socket.timeout:
                logger.warning("Keine Daten mehr (Timeout). Download wahrscheinlich fertig.")
                break
            except KeyboardInterrupt:
                break
        
        # Save File
        logger.info(f"Speichere Bild aus {len(received_chunks)} Chunks...")
        with open("downloaded_image.jpg", "wb") as f:
            for seq in sorted(received_chunks.keys()):
                f.write(received_chunks[seq])
        logger.info("✅ Datei 'downloaded_image.jpg' gespeichert.")


    def run(self):
        ping_thread = None
        try:
            if self.setup_network():
                ping_thread = NetworkPinger(TARGET_IP)
                ping_thread.start()

                if self.discover_and_login():
                    logger.info(">>> Handshake...")
                    # 1. Hello
                    self.simple_send(ARTEMIS_HELLO_BODY)
                    time.sleep(0.1)
                    # 2. Magic Packets
                    self.simple_send(MAGIC_BODY_1, 0xD1)
                    time.sleep(0.05)
                    self.simple_send(MAGIC_BODY_2, 0xD1)
                    time.sleep(1.0) # Warten auf Stabilisierung
                    
                    logger.info(">>> Sende 'Get Picture' Kommando...")
                    self.simple_send(CMD_GET_PICTURE)
                    
                    # Wechsel in den Download Modus
                    self.download_loop()

                else: logger.error("❌ Discovery Failed.")
        except KeyboardInterrupt:
            logger.info("Abbruch durch Benutzer.")
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
        logger.warning("⚠️  Bitte als root starten für WLAN/Ping!")

    if args.ble:
        asyncio.run(BLEWorker.wake_camera(BLE_MAC))
        time.sleep(20)

    if args.wifi:
        WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS)

    Session().run()
