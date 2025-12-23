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

# --- PAYLOADS AUS FRIDA LOG ---

# LBCS (Magic: F1 41) - Discovery
LBCS_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")

# Source 54: ARTEMIS Hello (Der Session-Starter)
ARTEMIS_HELLO = bytes.fromhex(
    "f1d000c5d1000000415254454d495300"  # Header + ARTEMIS
    "0200000001000000ad0000004a385757"
    "755144506d59534c66752f675841472b"
    "557162427935354b5032694532355150"
    "4e6f667a6e3034302b4e493967377a65"
    "584c6b497058704330375358766f7372"
    "577363316d386d786e7136684d694b77"
    "6550624b4a5577765376715a62367330"
    "736c3173667a68326d7452736c56324e"
    "633674524b6f78472f516a2b70337947"
    "6c314343354152624a4a4b4742615863"
    "677137546e656b6e2b7974772b524c6c"
    "676f53414d4f633d00"
)

# Source 57: Heartbeat / Status Ack
HEARTBEAT_PAYLOAD = bytes.fromhex(
    "f1d1000ed100000500000000000000000000"
)

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
        # 1. Prüfen, ob wir schon verbunden sind
        try:
            iw_out = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True).stdout.strip()
            if iw_out == ssid:
                logger.info(f"WLAN bereits mit {ssid} verbunden.")
                return True
        except: pass
        
        logger.info("Verbinde WLAN...")
        
        # 2. WICHTIG: Altes Profil löschen, um den "key-mgmt" Fehler zu beheben
        subprocess.run(["sudo", "nmcli", "c", "delete", ssid], capture_output=True)
        
        # 3. Scan erzwingen
        subprocess.run(["sudo", "nmcli", "d", "wifi", "rescan"], capture_output=True)
        time.sleep(3) # Kurz warten, damit Scan Ergebnisse da sind
        
        # 4. Verbinden mit expliziter Angabe des Interfaces (wlan0)
        cmd = ["sudo", "nmcli", "d", "wifi", "connect", ssid, "password", password, "ifname", "wlan0"]
        res = subprocess.run(cmd, capture_output=True)
        
        if res.returncode == 0:
            logger.info("WLAN verbunden.")
            return True
            
        # Detaillierte Fehlerausgabe dekodieren für Log
        err_msg = res.stderr.decode('utf-8', errors='ignore').strip()
        logger.error(f"WLAN Fehler: {err_msg}")
        return False

class Session:
    def __init__(self):
        self.sock = None
        self.local_ip = None
        self.active_port = None
        self.running = True

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

    def discover(self):
        logger.info(f"Starte Discovery auf Ports {TARGET_PORTS}...")
        ips = ["255.255.255.255", TARGET_IP]

        for attempt in range(5):
            for port in TARGET_PORTS:
                for ip in ips:
                    try: self.sock.sendto(LBCS_PAYLOAD, (ip, port))
                    except: pass

            start = time.time()
            while time.time() - start < 1.0:
                try:
                    data, addr = self.sock.recvfrom(4096)
                    # Suche nach F1 42 (LBCS Response) oder F1 D0 (ACK)
                    if len(data) >= 4 and data[0] == 0xF1:
                         # 0x42 = LBCS Resp, 0xD0 = ACK (Manchmal antwortet sie schon mit ACK)
                        if data[1] == 0x42 or data[1] == 0xD0:
                            logger.info(f"✅ ANTWORT von {addr[0]}:{addr[1]}")
                            self.active_port = addr[1]
                            return True
                except socket.timeout: pass
                except OSError: pass
            time.sleep(0.5)
        return False

    def login(self):
        if not self.active_port: return False
        
        payload = { "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }
        json_str = json.dumps(payload, separators=(',', ':'))
        
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))
        
        # 0xF9 = PRE_LOGIN Command
        pkt = struct.pack('>BBH', 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + encrypted)) + \
              PHASE2_STATIC_HEADER + encrypted
        
        logger.info(f"Sende Login an {TARGET_IP}:{self.active_port}...")
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))
        
        # Wir warten kurz auf die Bestätigung
        try:
            data, _ = self.sock.recvfrom(4096)
            if data:
                logger.info(f"✅ Login Antwort erhalten ({len(data)} bytes).")
                return True
        except:
            logger.warning("Keine direkte Login-Antwort, versuche trotzdem Handshake...")
            return True 
        return True

    def run(self):
        try:
            if self.setup_network():
                if self.discover():
                    if self.login():
                        
                        # --- ARTEMIS HANDSHAKE ---
                        logger.info(">>> Sende ARTEMIS Hello (Session Start)...")
                        self.sock.sendto(ARTEMIS_HELLO, (TARGET_IP, self.active_port))
                        time.sleep(0.2)
                        
                        logger.info(">>> Verbindung stabil. Warte auf Events (Spam wird gefiltert)...")
                        
                        last_send = time.time()
                        errors = 0
                        
                        while self.running:
                            now = time.time()
                            
                            # 1. Empfangen & Filtern
                            try:
                                data, addr = self.sock.recvfrom(4096)
                                d_len = len(data)
                                d_hex = data.hex()

                                # --- FILTER LOGIK ---
                                if d_len in [40, 157]: 
                                    pass # Standard Status-Pakete
                                elif d_len == 11 and d_hex.endswith("41434b"): 
                                    pass # ACK Pakete
                                elif d_len == 4 and d_hex == "f1e00000":
                                    pass # Ping Antwort
                                else:
                                    logger.info(f"📩 RX [{d_len}]: {d_hex[:60]}...")

                            except socket.timeout:
                                pass
                            except OSError:
                                logger.error("Netzwerkfehler beim Empfangen")
                                break
                            
                            # 2. Senden (Heartbeat alle 2 Sekunden)
                            if now - last_send > 2.0:
                                try:
                                    self.sock.sendto(HEARTBEAT_PAYLOAD, (TARGET_IP, self.active_port))
                                    last_send = now
                                    errors = 0
                                    # Optional: print(".", end="", flush=True) 
                                except OSError as e:
                                    logger.error(f"❌ Sendefehler: {e}")
                                    errors += 1
                                    if errors > 5: break
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
