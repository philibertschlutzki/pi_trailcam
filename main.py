import socket
import struct
import time
import json
import logging
import sys
import argparse
import subprocess
import asyncio
import base64
import os
from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# --- KONFIGURATION (AUS DEINEM LOGFILE) ---
DEFAULT_CAMERA_IP = "192.168.43.1"   # Bestätigt durch Log
DEFAULT_CAMERA_PORT = 40611          # Bestätigt durch Log: remoteAddr:(...:40611)
DEFAULT_WIFI_SSID = "KJK_E0FF"
DEFAULT_WIFI_PASS = "85087127"
DEFAULT_BLE_MAC = "C6:1E:0D:E0:32:E8"

# BLE Konstanten
BLE_UUID_WRITE = "00000002-0000-1000-8000-00805f9b34fb"
BLE_WAKEUP_BYTES = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# EXAKTER LBCS HANDSHAKE PAYLOAD
# Magic: F1 41, Length: 20 Bytes (0x14)
# Content: LBCS + Null-Padding + CCCJJ + Null-Padding
LBCS_HANDSHAKE_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")

# Token aus Log (Session ID muss später angehängt werden)
TEST_BLE_TOKEN = "J8WWuQDPmYSLfu/gXAG+UqbBy55KP2iE25QPNofzn040+NI9g7zeXLkIpXpC07SXvosrWsc1m8mxnq6hMiKwePbKJUwvSvqZb6s0sl1sfzh2mtRslV2Nc6tRKoxG/Qj+p3yGl1CC5ARbJJKGBaXcgq7Tnekn+ytw+RLlgoSAMOc="

# Crypto (Artemis Standard)
PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ArtemisClient")

# --- PROTOKOLL TYPEN ---
class PacketType:
    LBCS_REQ = 0x41
    LBCS_RESP = 0x43  
    DATA = 0xD0
    CONTROL = 0xD1
    PRE_LOGIN = 0xF9
    WAKEUP_1 = 0xE0
    WAKEUP_2 = 0xE1

class BLEWorker:
    @staticmethod
    async def wake_camera(mac_address):
        logger.info(f"Suche BLE Gerät {mac_address}...")
        try:
            device = await BleakScanner.find_device_by_address(mac_address, timeout=45.0)
            if not device:
                logger.warning("❌ BLE Gerät nicht gefunden.")
                return False

            logger.info(f"Gerät gefunden! Verbinde...")
            async with BleakClient(device, timeout=15.0) as client:
                logger.info("BLE Connected. Sending Wakeup Magic Bytes...")
                await client.write_gatt_char(BLE_UUID_WRITE, BLE_WAKEUP_BYTES, response=True)
                logger.info("✅ BLE Wakeup Sent.")
                return True
        except Exception as e:
            logger.error(f"BLE Error: {e}")
            return False

class WiFiWorker:
    @staticmethod
    def connect_nmcli(ssid, password):
        logger.info(f"Connecting to WiFi {ssid} via nmcli...")
        try:
            res = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
            if ssid in res.stdout.strip():
                logger.info("Already connected to correct WiFi.")
                return True
        except FileNotFoundError: pass 

        subprocess.run(["sudo", "nmcli", "connection", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], capture_output=True)
        time.sleep(3)
        cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", password]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode == 0:
            logger.info("WiFi Connected.")
            return True
        else:
            logger.error(f"WiFi Connection Failed: {proc.stderr.strip()}")
            return False

class PPPPSession:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.sock = None
        self.session_id = None
        self.control_seq = 0

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Binde an zufälligen lokalen Port, ähnlich wie im Log "port:35281"
        self.sock.bind(('0.0.0.0', 0)) 
        self.sock.settimeout(2.0)
        logger.info(f"Lokaler UDP Socket gebunden an Port: {self.sock.getsockname()[1]}")

    def close(self):
        if self.sock: self.sock.close()

    def _send(self, data):
        if not self.sock: return
        try:
            self.sock.sendto(data, (self.ip, self.port))
        except Exception as e:
            logger.error(f"Send Error: {e}")

    def _recv(self, timeout=None):
        if not self.sock: return None
        if timeout: self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(4096)
            return data
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Recv Error: {e}")
            return None

    # --- PHASE 1: LBCS DISCOVERY / HANDSHAKE ---
    def phase1_handshake(self):
        # Wir senden EXAKT das Paket, das wir kennen
        packet = LBCS_HANDSHAKE_PAYLOAD
        
        logger.info(f"Sende LBCS Handshake an {self.ip}:{self.port}")
        for i in range(3):
            self._send(packet)
            
            resp = self._recv(timeout=1.5)
            if resp and len(resp) >= 4:
                magic, ptype, _ = struct.unpack('>BBH', resp[:4])
                
                # Prüfe auf korrekte Antwort (0xF1 0x43 ...)
                if magic == 0xF1 and ptype == PacketType.LBCS_RESP:
                    logger.info(f"✅ LBCS Handshake erfolgreich! (Typ 0x43)")
                    
                    # Session ID extrahieren (Bytes 24-28 im Response)
                    if len(resp) >= 28:
                        self.session_id = resp[24:28]
                        logger.info(f"🔑 Session ID: {self.session_id.hex()}")
                    return True
                else:
                    logger.debug(f"Ignoriere Paket: Magic={hex(magic)} Type={hex(ptype)}")
            
            logger.info("Keine/Falsche Antwort, Retry...")
            time.sleep(1.0)
            
        return False

    # --- PHASE 2: LOGIN / CRYPTO ---
    def phase2_pre_login(self):
        # JSON Payload vorbereiten
        payload_dict = {
            "utcTime": int(time.time()),
            "nonce": os.urandom(8).hex()
        }
        json_str = json.dumps(payload_dict, separators=(',', ':'))
        
        # Verschlüsseln
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))
        
        full_content = PHASE2_STATIC_HEADER + encrypted
        header = struct.pack('>BBH', 0xF1, PacketType.PRE_LOGIN, len(full_content))
        packet = header + full_content
        
        logger.info("Sende Pre-Login (Crypto Init)...")
        for i in range(3):
            self._send(packet)
            resp = self._recv(timeout=1.0)
            if resp:
                logger.info("✅ Pre-Login Antwort erhalten.")
                return True
        return True # Wir machen weiter, auch wenn kein explizites ACK kommt (UDP)

    def heartbeat_loop(self):
        logger.info(">>> Starte Heartbeat Loop (Alle 3s)...")
        last_beat = 0
        while True:
            if time.time() - last_beat > 3.0:
                # Nutze LBCS Paket als Heartbeat
                self._send(LBCS_HANDSHAKE_PAYLOAD)
                last_beat = time.time()
                
            # Höre auf Pakete
            data = self._recv(timeout=0.1)
            if data and len(data) > 0:
                # Optional: Hier könnte man eingehende Daten parsen
                pass

    def run(self):
        self.connect()
        try:
            if self.phase1_handshake():
                self.phase2_pre_login()
                self.heartbeat_loop()
            else:
                logger.error("❌ Handshake fehlgeschlagen auf Port 40611.")
        finally:
            self.close()

# --- MAIN ---

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wifi", action="store_true", help="WiFi Connect")
    parser.add_argument("--ble", action="store_true", help="BLE Wakeup")
    args = parser.parse_args()

    # 1. BLE
    if args.ble:
        if asyncio.run(BLEWorker.wake_camera(DEFAULT_BLE_MAC)):
            logger.info("Warte 15s auf WLAN...")
            time.sleep(15)

    # 2. WiFi
    if args.wifi:
        if not WiFiWorker.connect_nmcli(DEFAULT_WIFI_SSID, DEFAULT_WIFI_PASS):
            return

    # 3. UDP Session (Port 40611 fix!)
    logger.info(f"[*] Starte Session zu {DEFAULT_CAMERA_IP}:{DEFAULT_CAMERA_PORT}...")
    session = PPPPSession(DEFAULT_CAMERA_IP, DEFAULT_CAMERA_PORT)
    session.run()

if __name__ == "__main__":
    main()
