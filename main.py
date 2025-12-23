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

# PAYLOADS
# LBCS (Magic: F1 41) - Discovery
LBCS_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")
# Wakeup (Magic: F1 E0 / F1 E1)
WAKEUP_1 = bytes.fromhex("f1e00000")
WAKEUP_2 = bytes.fromhex("f1e10000")

# Crypto
PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("CamClient")

class PacketType:
    LBCS_RESP = 0x43
    PRE_LOGIN = 0xF9
    HEARTBEAT = 0xF5 # Annahme: Oft ist F5 oder AA ein Heartbeat/Status Command

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
            # Check if strictly connected to the specific SSID
            iw_out = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True).stdout.strip()
            if iw_out == ssid:
                logger.info(f"WLAN bereits mit {ssid} verbunden.")
                return True
        except: pass
        
        logger.info("Verbinde WLAN...")
        # Force rescan helps sometimes
        subprocess.run(["sudo", "nmcli", "d", "wifi", "rescan"], capture_output=True)
        time.sleep(1)
        
        res = subprocess.run(["sudo", "nmcli", "d", "wifi", "connect", ssid, "password", password], 
                           capture_output=True)
        
        if res.returncode == 0:
            logger.info("WLAN verbunden.")
            return True
        
        logger.error(f"WLAN Fehler: {res.stderr}")
        return False

class Session:
    def __init__(self):
        self.sock = None
        self.local_ip = None
        self.active_port = None
        self.running = True

    def setup_network(self):
        # Einfacherer Weg die IP zu finden, die zum Ziel routet
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((TARGET_IP, 1))
            self.local_ip = s.getsockname()[0]
            s.close()
        except:
            logger.error("❌ Netzwerk nicht bereit. Ist das WLAN verbunden?")
            return False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        try:
            self.sock.bind((self.local_ip, FIXED_LOCAL_PORT))
            logger.info(f"Socket gebunden an {self.local_ip}:{FIXED_LOCAL_PORT}")
        except:
            self.sock.bind((self.local_ip, 0))
            logger.info(f"Fixed Port belegt, nutze Ephemeral Port: {self.sock.getsockname()[1]}")
        
        self.sock.settimeout(1.0) # Etwas höherer Timeout
        return True

    def discover(self):
        logger.info(f"Starte Discovery auf Ports {TARGET_PORTS}...")
        # Nur Broadcast und Ziel-IP reichen meist
        ips = ["255.255.255.255", TARGET_IP]

        for attempt in range(10):
            for port in TARGET_PORTS:
                for ip in ips:
                    try: self.sock.sendto(LBCS_PAYLOAD, (ip, port))
                    except: pass

            # Hören
            start = time.time()
            while time.time() - start < 1.0:
                try:
                    data, addr = self.sock.recvfrom(4096)
                    if len(data) >= 4 and data[0] == 0xF1:
                        logger.info(f"✅ ANTWORT von {addr[0]}:{addr[1]} | Len: {len(data)}")
                        logger.info(f"   Hex: {data.hex()}")
                        self.active_port = addr[1]
                        return True
                except socket.timeout: pass
                except OSError: pass # Interface down catch
            
            logger.info(f"Discovery Versuch {attempt+1}...")
            time.sleep(0.5)
        
        return False

    def login(self):
        if not self.active_port: return False
        
        payload = { "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }
        json_str = json.dumps(payload, separators=(',', ':'))
        
        # Padding Logik prüfen (PKCS7 Standard ist oft block_size)
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        padded_data = pad(json_str.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        
        pkt = struct.pack('>BBH', 0xF1, PacketType.PRE_LOGIN, len(PHASE2_STATIC_HEADER + encrypted)) + \
              PHASE2_STATIC_HEADER + encrypted
        
        logger.info(f"Sende Login ({len(pkt)} bytes) an {TARGET_IP}:{self.active_port}...")
        
        for _ in range(3):
            self.sock.sendto(pkt, (TARGET_IP, self.active_port))
            try:
                data, _ = self.sock.recvfrom(4096)
                if data: 
                    # --- HIER IST DAS LOGGING VERBESSERT ---
                    logger.info("✅ Login OK! Empfangene Daten:")
                    logger.info(f"   Len: {len(data)}")
                    logger.info(f"   Hex: {data.hex()}")
                    logger.info(f"   ASCII (Teilweise): {data[10:].decode('utf-8', errors='ignore')}")
                    return True
            except socket.timeout: pass
            except Exception as e: logger.error(f"Login Fehler: {e}")
            
        logger.warning("Keine Login-Antwort erhalten, mache trotzdem weiter...")
        return True # Wir machen weiter, vielleicht hat es geklappt aber Paket verloren

    def run(self):
        try:
            if self.setup_network():
                if self.discover():
                    if self.login():
                        logger.info(">>> Verbindung etabliert. Starte Heartbeat-Loop...")
                        
                        last_send = time.time()
                        errors = 0
                        
                        while self.running:
                            now = time.time()
                            
                            # 1. Empfangen (Hören, ob Kamera was will)
                            try:
                                data, addr = self.sock.recvfrom(4096)
                                logger.info(f"📩 RX [{len(data)}]: {data.hex()}")
                                # Hier könnten wir später auf Pings antworten
                            except socket.timeout:
                                pass # Normal, wenn keine Daten kommen
                            except OSError as e:
                                logger.error(f"❌ Socket Fehler (Netzwerk weg?): {e}")
                                errors += 1
                                if errors > 5: break
                            
                            # 2. Senden (Heartbeat alle 2 Sekunden)
                            if now - last_send > 2.0:
                                try:
                                    # Vorerst weiter LBCS senden, bis wir das Login-Paket analysiert haben
                                    self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, self.active_port))
                                    # logger.debug("Ping gesendet...") 
                                    last_send = now
                                    errors = 0 # Reset error counter on successful send
                                except OSError as e:
                                    logger.error(f"❌ Sendefehler: {e}")
                                    errors += 1
                                    if errors > 3: 
                                        logger.error("Zu viele Fehler. Abbruch.")
                                        break
                else:
                    logger.error("❌ Kamera antwortet nicht.")
        except KeyboardInterrupt:
            logger.info("Benutzerabbruch.")
        finally:
            if self.sock: 
                self.sock.close()
                logger.info("Socket geschlossen.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wifi", action="store_true")
    parser.add_argument("--ble", action="store_true")
    args = parser.parse_args()

    # Root Check für WiFi/BLE notwendig oft
    if os.geteuid() != 0:
        logger.warning("Achtung: Script läuft nicht als Root. WiFi/BLE könnte fehlschlagen.")

    if args.ble:
        if asyncio.run(BLEWorker.wake_camera(BLE_MAC)):
            logger.info("Warte 15s auf Kamera-WLAN...")
            time.sleep(15) 
    
    if args.wifi:
        if not WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS):
            sys.exit(1)

    Session().run()
