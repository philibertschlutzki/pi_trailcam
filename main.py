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
# Wir probieren Port 40611 (aus Log) und 3333 (Standard Discovery)
TARGET_PORTS = [40611, 3333]
FIXED_LOCAL_PORT = 35281

DEFAULT_SSID = "KJK_E0FF"
DEFAULT_PASS = "85087127"
BLE_MAC = "C6:1E:0D:E0:32:E8"

# PAYLOADS
# LBCS (Magic: F1 41)
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
        except: return False

class WiFiWorker:
    @staticmethod
    def connect(ssid, password):
        try:
            if ssid in subprocess.run(["iwgetid", "-r"], capture_output=True, text=True).stdout:
                logger.info("WLAN bereits verbunden.")
                return True
        except: pass
        logger.info("Verbinde WLAN...")
        subprocess.run(["sudo", "nmcli", "c", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "d", "wifi", "rescan"], capture_output=True)
        time.sleep(2)
        if subprocess.run(["sudo", "nmcli", "d", "wifi", "connect", ssid, "password", password], 
                         capture_output=True).returncode == 0:
            logger.info("WLAN verbunden.")
            return True
        return False

class Session:
    def __init__(self):
        self.sock = None
        self.local_ip = None
        self.active_port = None

    def setup_network(self):
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for link in addrs[netifaces.AF_INET]:
                    if link['addr'].startswith("192.168.43."):
                        self.local_ip = link['addr']
                        break
        
        if not self.local_ip:
            logger.error("❌ Keine IP im 192.168.43.x Netz gefunden!")
            return False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        try:
            self.sock.bind((self.local_ip, FIXED_LOCAL_PORT))
            logger.info(f"Socket gebunden an {self.local_ip}:{FIXED_LOCAL_PORT} (Wie Android)")
        except:
            self.sock.bind((self.local_ip, 0))
            logger.info(f"Fixed Port belegt, nutze {self.sock.getsockname()[1]}")
        
        self.sock.settimeout(0.5)
        return True

    def discover(self):
        subnet_bc = self.local_ip.rsplit('.', 1)[0] + ".255"
        
        # Liste der Ziele: Broadcast Subnet, Broadcast Global, Unicast
        ips = [subnet_bc, "255.255.255.255", TARGET_IP]

        logger.info(f"Starte Discovery auf Ports {TARGET_PORTS}...")

        for attempt in range(15):
            for port in TARGET_PORTS:
                for ip in ips:
                    # Strategie: Einfach alles senden. Die Kamera pickt sich das richtige raus.
                    # 1. LBCS Handshake (Das wichtigste Discovery Paket)
                    try: self.sock.sendto(LBCS_PAYLOAD, (ip, port))
                    except: pass
                    
                    # 2. Wakeup Sequence (Falls LBCS allein nicht reicht)
                    try: 
                        self.sock.sendto(WAKEUP_1, (ip, port))
                        self.sock.sendto(WAKEUP_2, (ip, port))
                    except: pass

                # Hören
                start = time.time()
                while time.time() - start < 0.5:
                    try:
                        data, addr = self.sock.recvfrom(4096)
                        if len(data) >= 4 and data[0] == 0xF1:
                            logger.info(f"✅ ANTWORT von {addr[0]}:{addr[1]} | Len: {len(data)}")
                            logger.info(f"   Hex: {data.hex()}")
                            self.active_port = addr[1]
                            return True
                    except socket.timeout: pass
                    except Exception as e: logger.error(e)
            
            logger.info(f"Versuch {attempt+1}: Sende Pings...")
            time.sleep(0.5)
        
        return False

    def login(self):
        if not self.active_port: return False
        
        payload = { "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }
        json_str = json.dumps(payload, separators=(',', ':'))
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))
        
        pkt = struct.pack('>BBH', 0xF1, PacketType.PRE_LOGIN, len(PHASE2_STATIC_HEADER + encrypted)) + \
              PHASE2_STATIC_HEADER + encrypted
        
        logger.info(f"Sende Login an {TARGET_IP}:{self.active_port}...")
        for _ in range(3):
            self.sock.sendto(pkt, (TARGET_IP, self.active_port))
            try:
                data, _ = self.sock.recvfrom(4096)
                if data: 
                    logger.info("✅ Login OK (Daten empfangen)")
                    return True
            except: pass
        return True

    def run(self):
        if self.setup_network():
            if self.discover():
                self.login()
                logger.info(">>> Verbindung steht. Script läuft endlos...")
                while True:
                    time.sleep(3)
                    self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, self.active_port))
            else:
                logger.error("❌ Kamera antwortet auf keinem Port.")
        if self.sock: self.sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wifi", action="store_true")
    parser.add_argument("--ble", action="store_true")
    args = parser.parse_args()

    if args.ble:
        if asyncio.run(BLEWorker.wake_camera(BLE_MAC)):
            time.sleep(15) # Wichtig: Kamera braucht Zeit zum Starten des WLANs
    
    if args.wifi:
        if not WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS):
            sys.exit(1)

    Session().run()
