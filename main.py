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

# Magic Handshake Bodies (Null-Payloads)
MAGIC_BODY_1 = bytes.fromhex("000000000000") 
MAGIC_BODY_2 = bytes.fromhex("0000")         

# Heartbeat
HEARTBEAT_BODY_START = bytes.fromhex("415254454d49530002000000") 
HEARTBEAT_PAYLOAD_END = bytes.fromhex("000100190000004d7a6c423336582f49566f385a7a49357247396a31773d3d00")

# Crypto
PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("CamClient")

# --- WORKERS ---

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
        logger.info("📡 Background ICMP Ping gestartet.")
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
    def __init__(self):
        self.sock = None
        self.active_port = None
        self.running = True
        self.global_seq = 0 
        self.cmd_cnt = 1    

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
        # Preamble D1 00 00 Seq (4 bytes) + Payload
        body_len = len(payload) + 4 
        
        header = bytearray()
        header.append(0xF1)
        header.append(packet_type)
        header.append((body_len >> 8) & 0xFF)
        header.append(body_len & 0xFF)
        
        header.append(0xD1) # Preamble Start
        header.append(0x00)
        header.append(0x00)
        header.append(seq)
        
        return header + payload, seq

    def build_heartbeat(self):
        self.cmd_cnt = (self.cmd_cnt + 1) % 255
        body = bytearray()
        body.extend(HEARTBEAT_BODY_START)
        body.append(self.cmd_cnt)   
        body.extend(HEARTBEAT_PAYLOAD_END)
        return self.build_rudp_packet(0xD0, body) 

    def build_ack(self, rx_seq):
        # ACK payload: 00 [Seq] 00 [Seq]
        payload = bytearray([0x00, rx_seq, 0x00, rx_seq])
        return self.build_rudp_packet(0xD1, payload)[0]

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

        logger.info(f"Sende Login an {TARGET_IP}:{self.active_port}...")
        payload = { "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }
        enc = AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(pad(json.dumps(payload, separators=(',', ':')).encode(), AES.block_size))
        pkt = struct.pack('>BBH', 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + enc)) + PHASE2_STATIC_HEADER + enc
        
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))
        
        try:
            data, _ = self.sock.recvfrom(1024)
            if data: logger.info("✅ Login Antwort erhalten.")
        except: pass 
        
        return True

    def run(self):
        ping_thread = None
        try:
            if self.setup_network():
                ping_thread = NetworkPinger(TARGET_IP)
                ping_thread.start()

                if self.discover_and_login():
                    
                    logger.info(">>> Sende Handshake...")
                    # 1. Hello
                    pkt, seq = self.build_rudp_packet(0xD0, ARTEMIS_HELLO_BODY)
                    self.sock.sendto(pkt, (TARGET_IP, self.active_port))
                    time.sleep(0.05)
                    
                    # 2. Magic 1
                    pkt, seq = self.build_rudp_packet(0xD1, MAGIC_BODY_1)
                    self.sock.sendto(pkt, (TARGET_IP, self.active_port))
                    time.sleep(0.02)
                    
                    # 3. Magic 2
                    pkt, seq = self.build_rudp_packet(0xD1, MAGIC_BODY_2)
                    self.sock.sendto(pkt, (TARGET_IP, self.active_port))
                    
                    logger.info(">>> VERBINDUNG STABILISIERT (Strict Stop-and-Wait)...")
                    
                    last_send = 0
                    last_stats = time.time()
                    
                    # State Machine
                    pending_packet = None
                    pending_seq = 0
                    waiting_for_ack = False
                    
                    last_retry_time = 0
                    
                    rx_count = 0
                    tx_count = 0
                    
                    while self.running:
                        now = time.time()
                        
                        # --- A) EMPFANGEN ---
                        # Wir lesen erst alle verfügbaren Pakete, um ACKs zu finden
                        try:
                            while True:
                                data, _ = self.sock.recvfrom(4096)
                                if len(data) > 4 and data[0] == 0xF1:
                                    
                                    # DATA (D0) -> Wir müssen ACKen
                                    if data[1] == 0xD0:
                                        rx_seq = data[7]
                                        # ACK senden (ohne auf Antwort zu warten, "Fire and Forget")
                                        ack_pkt = self.build_ack(rx_seq)
                                        self.sock.sendto(ack_pkt, (TARGET_IP, self.active_port))
                                        rx_count += 1
                                    
                                    # ACK (D1) -> Unser Paket wurde bestätigt!
                                    elif data[1] == 0xD1:
                                        if waiting_for_ack:
                                            # Streng genommen müssten wir prüfen, ob das ACK zur pending_seq passt.
                                            # Aber im Log sieht man: ACK Payload ist "00 Seq 00 Seq".
                                            # Check Byte 5 (Payload Start) + 1 = Byte 6
                                            # Preamble (4) + 00 + Seq = Byte 9 in packet?
                                            # Vereinfachung: Wenn ACK kommt, gehen wir davon aus, es passt.
                                            waiting_for_ack = False
                                            rx_count += 1
                        except socket.timeout:
                            pass
                        except OSError:
                            break

                        # --- B) SENDEN ---
                        if not waiting_for_ack:
                            # Neues Paket senden (alle 1.5s)
                            if now - last_send > 1.5:
                                pending_packet, pending_seq = self.build_heartbeat()
                                try:
                                    self.sock.sendto(pending_packet, (TARGET_IP, self.active_port))
                                    tx_count += 1
                                    last_send = now
                                    waiting_for_ack = True
                                    last_retry_time = now
                                except OSError:
                                    waiting_for_ack = False # Network Error, retry later
                        else:
                            # RETRANSMIT (STRICT!)
                            # Wenn wir auf ACK warten und Timeout abgelaufen ist:
                            if now - last_retry_time > 0.8:
                                # logger.info(f"Retrying Seq {pending_seq}...")
                                try:
                                    self.sock.sendto(pending_packet, (TARGET_IP, self.active_port))
                                    last_retry_time = now
                                except OSError: pass
                                # WICHTIG: Wir bleiben auf waiting_for_ack = True!
                                # Wir machen KEIN next_seq(), wir geben NICHT auf.
                        
                        # --- C) STATS ---
                        if now - last_stats > 10.0:
                            state = "WAIT" if waiting_for_ack else "IDLE"
                            logger.info(f"♻️  Stats: TX: {tx_count} | RX: {rx_count} | Seq: {self.global_seq} | State: {state}")
                            rx_count = 0; tx_count = 0; last_stats = now

                else: logger.error("❌ Discovery Failed.")
        except KeyboardInterrupt:
            logger.info("Ende.")
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
