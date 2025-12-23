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
import netifaces
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

# --- KONSTANTEN ---
LBCS_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")

# Base64 Payload aus deinem Log (MzlB...)
HEARTBEAT_DATA = bytes.fromhex("4d7a6c423336582f49566f385a7a49357247396a31773d3d00")

# Crypto
PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("CamClient")

class BLEWorker:
    @staticmethod
    async def wake_camera(mac):
        logger.info(f"Suche BLE {mac}...")
        try:
            dev = await BleakScanner.find_device_by_address(mac, timeout=45.0)
            if not dev: return False
            async with BleakClient(dev, timeout=15.0) as client:
                await client.write_gatt_char("00000002-0000-1000-8000-00805f9b34fb", 
                                             bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]), 
                                             response=True)
                logger.info("✅ BLE Wakeup gesendet.")
                return True
        except Exception as e:
            logger.error(f"BLE Error: {e}")
            return False

class WiFiWorker:
    @staticmethod
    def connect(ssid, password):
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
        cmd = ["sudo", "nmcli", "d", "wifi", "connect", ssid, "password", password, "ifname", "wlan0"]
        res = subprocess.run(cmd, capture_output=True)
        if res.returncode == 0:
            logger.info("WLAN verbunden.")
            return True
        err_msg = res.stderr.decode('utf-8', errors='ignore').strip()
        logger.error(f"WLAN Fehler: {err_msg}")
        return False

class Session:
    def __init__(self):
        self.sock = None
        self.local_ip = None
        self.active_port = None
        self.running = True
        
        # Zähler initialisieren (wie im Log gesehen ca. bei 0x16 gestartet, wir fangen bei 1 an)
        self.seq_num = 1
        self.hb_cnt = 1

    def setup_network(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((TARGET_IP, 1))
            self.local_ip = s.getsockname()[0]
            s.close()
        except:
            logger.error("❌ Netzwerk nicht bereit.")
            return False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        try:
            self.sock.bind((self.local_ip, FIXED_LOCAL_PORT))
            logger.info(f"Socket gebunden an {self.local_ip}:{FIXED_LOCAL_PORT}")
        except:
            self.sock.bind((self.local_ip, 0))
            logger.info(f"Port belegt, nutze {self.sock.getsockname()[1]}")
        
        self.sock.settimeout(1.0)
        return True

    def get_next_seq(self):
        self.seq_num = (self.seq_num + 1) % 255
        if self.seq_num == 0: self.seq_num = 1 # 0 vermeiden falls nötig
        return self.seq_num

    def build_heartbeat(self):
        # Wir bauen das 53-Byte Paket manuell nach Struktur aus Log
        # Header: f1 d0 00 31 d1 00 00 [SEQ]
        seq = self.get_next_seq()
        
        # Payload Counter
        self.hb_cnt = (self.hb_cnt + 1) % 255
        
        # ARTEMIS Header
        # 41 52 54 45 4d 49 53 00 
        # 02 00 00 00 (Cmd?)
        # [HB_CNT] 00 01 00 (Counter an Byte 20)
        # 19 00 00 00 (Len Data?)
        
        pkt = bytearray()
        pkt.extend(bytes.fromhex("f1d00031d10000"))
        pkt.append(seq)
        pkt.extend(bytes.fromhex("415254454d495300")) # ARTEMIS
        pkt.extend(bytes.fromhex("02000000"))         # Type
        pkt.append(self.hb_cnt)                       # Counter an Stelle 20
        pkt.extend(bytes.fromhex("00010019000000"))   # Padding/Len
        pkt.extend(HEARTBEAT_DATA)                    # "MzlB..."
        
        return pkt

    def build_ack(self, rx_seq):
        # Einfaches ACK Paket: f1 d1 ... [SEQ]
        # Im Log: f1 d1 00 08 d1 00 00 02 00 [RX_SEQ] 00 [RX_SEQ]
        # Wir versuchen ein simples ACK
        my_seq = self.get_next_seq()
        
        pkt = bytearray()
        pkt.extend(bytes.fromhex("f1d10008d10000"))
        pkt.append(my_seq)
        
        # Payload: Einfach die empfangene Sequenz wiederholen
        pkt.append(0x00)
        pkt.append(rx_seq)
        pkt.append(0x00)
        pkt.append(rx_seq)
        
        return pkt

    def discover(self):
        logger.info(f"Starte Discovery auf Ports {TARGET_PORTS}...")
        for attempt in range(3):
            for port in TARGET_PORTS:
                try: self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, port))
                except: pass
            
            start = time.time()
            while time.time() - start < 1.0:
                try:
                    data, addr = self.sock.recvfrom(4096)
                    if len(data) >= 4 and data[0] == 0xF1:
                        if data[1] == 0x42 or data[1] == 0xD0:
                            logger.info(f"✅ ANTWORT von {addr[0]}:{addr[1]}")
                            self.active_port = addr[1]
                            return True
                except: pass
        return False

    def login(self):
        if not self.active_port: return False
        
        payload = { "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }
        json_str = json.dumps(payload, separators=(',', ':'))
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))
        
        # Header bauen
        seq = self.get_next_seq()
        # Login ist f1 f9 ...
        # Wir nutzen statischen Headerbau hierfür, da Login einmalig ist
        # Aber seq anpassen wäre gut. Log zeigt f1 f9 00 54 ...
        
        pkt = struct.pack('>BBH', 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + encrypted)) + \
              PHASE2_STATIC_HEADER + encrypted
        
        logger.info(f"Sende Login an {TARGET_IP}:{self.active_port}...")
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))
        
        try:
            data, _ = self.sock.recvfrom(4096)
            if data:
                logger.info(f"✅ Login Antwort erhalten ({len(data)} bytes).")
                return True
        except:
            logger.warning("Keine Antwort, versuche trotzdem weiter...")
            return True
        return True

    def run(self):
        try:
            if self.setup_network():
                if self.discover():
                    if self.login():
                        
                        logger.info(">>> VERBINDUNG STABILISIERT. Sende 53-Byte Heartbeats...")
                        
                        last_send = time.time()
                        last_stats = time.time()
                        
                        rx_count = 0
                        tx_count = 0
                        
                        while self.running:
                            now = time.time()
                            
                            # 1. Senden (Heartbeat alle 1.5s)
                            if now - last_send > 1.5:
                                try:
                                    hb_pkt = self.build_heartbeat()
                                    self.sock.sendto(hb_pkt, (TARGET_IP, self.active_port))
                                    last_send = now
                                    tx_count += 1
                                except OSError as e:
                                    logger.error(f"❌ Sendefehler: {e}")
                                    break

                            # 2. Empfangen & ACKen
                            try:
                                data, addr = self.sock.recvfrom(4096)
                                rx_count += 1
                                d_len = len(data)
                                
                                # Wenn es ein Datenpaket ist (f1 d0 ...), müssen wir ACKen
                                if d_len > 8 and data[0] == 0xF1 and data[1] == 0xD0:
                                    rx_seq = data[7] # Sequenznummer extrahieren
                                    ack_pkt = self.build_ack(rx_seq)
                                    self.sock.sendto(ack_pkt, (TARGET_IP, self.active_port))
                                    
                            except socket.timeout:
                                pass
                            except OSError:
                                break
                            
                            # 3. Status Report (Alle 5s)
                            if now - last_stats > 5.0:
                                logger.info(f"♻️  Status: Verbunden | TX: {tx_count} | RX: {rx_count} | Seq: {self.seq_num}")
                                # Reset counters for easy reading of "packets per 5s"
                                rx_count = 0
                                tx_count = 0
                                last_stats = now

                else:
                    logger.error("❌ Kamera nicht gefunden.")
        except KeyboardInterrupt:
            logger.info("Abbruch durch User.")
        finally:
            if self.sock: self.sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wifi", action="store_true")
    parser.add_argument("--ble", action="store_true")
    args = parser.parse_args()

    if args.ble:
        if asyncio.run(BLEWorker.wake_camera(BLE_MAC)):
            time.sleep(15) 
    
    if args.wifi:
        if not WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS):
            sys.exit(1)

    Session().run()
