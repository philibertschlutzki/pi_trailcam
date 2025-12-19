import asyncio
import logging
import sys
import time
import struct
import socket
import subprocess
import json
from bleak import BleakScanner, BleakClient

# --- KONFIGURATION ---
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"
WIFI_SSID = "KJK_E0FF"
WIFI_PASS = "85087127"
WIFI_INTERFACE = "wlan0"

UUID_WRITE = "00000002-0000-1000-8000-00805f9b34fb" 
CMD_WAKEUP = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
ARTEMIS_TOKEN = "MzlB36X/IVo8ZzI5rG9j1w=="

# Standard IP (wird durch Discovery bestätigt)
CAMERA_IP = "192.168.43.1"
CAMERA_PORT = 40611 
LOCAL_PORT = 5085

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("KJK")

class BLEWorker:
    @staticmethod
    async def wake_camera_blindly():
        logger.info(f"PHASE 1: BLE Wakeup...")
        device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=8.0)
        if not device:
            logger.warning("Kamera BLE nicht gefunden. Weiter...")
            return True
        try:
            async with BleakClient(device) as client:
                logger.info("Sende Wake-Up...")
                try:
                    await client.write_gatt_char(UUID_WRITE, CMD_WAKEUP, response=True)
                except Exception: pass
        except Exception as e:
            logger.warning(f"BLE Fehler: {e}")
        return True

class WiFiWorker:
    @staticmethod
    def wait_and_connect(ssid, password, interface="wlan0"):
        logger.info(f"PHASE 2: WLAN Verbindung '{ssid}'...")
        subprocess.run(["sudo", "nmcli", "connection", "delete", ssid], capture_output=True)
        
        for i in range(15):
            subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan", "ifname", interface], capture_output=True)
            time.sleep(1)
            check = subprocess.run(["nmcli", "-f", "SSID", "device", "wifi", "list", "ifname", interface], capture_output=True, text=True)
            
            if ssid in check.stdout:
                logger.info(f"WLAN gefunden! Verbinde...")
                cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", password, "ifname", interface]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode == 0:
                    logger.info("✅ WLAN verbunden!")
                    return True
            time.sleep(2)
        return False

class UDPWorker:
    @staticmethod
    def create_packet(payload_bytes):
        # Header: F1 D0 + Length (2 Bytes Big Endian)
        header = struct.pack('>BBH', 0xF1, 0xD0, len(payload_bytes))
        return header + payload_bytes

    @staticmethod
    def start_session():
        logger.info("PHASE 3: UDP Discovery & Login...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try: sock.bind(('0.0.0.0', LOCAL_PORT))
        except: pass
        sock.settimeout(2.0)

        # --- A: DISCOVERY ---
        # Sende an Broadcast UND direkt an Gateway
        targets = [('255.255.255.255', 40611), ('255.255.255.255', 32108), (CAMERA_IP, 40611)]
        discovery_pkt = bytes.fromhex("f1300000")
        
        camera_addr = None
        logger.info("Sende Discovery...")
        
        for _ in range(3):
            for t in targets:
                try: sock.sendto(discovery_pkt, t)
                except: pass
            try:
                data, addr = sock.recvfrom(1024)
                logger.info(f"✅ Kamera gefunden bei {addr}!")
                camera_addr = addr
                break
            except socket.timeout: pass
        
        if not camera_addr:
            logger.warning("Keine Antwort auf Discovery. Versuche Standard-IP.")
            camera_addr = (CAMERA_IP, 40611)

        # --- B: INIT ---
        logger.info("Sende Init Pakete...")
        sock.sendto(bytes.fromhex("f1e00000"), camera_addr)
        time.sleep(0.1)
        sock.sendto(bytes.fromhex("f1e10000"), camera_addr)
        time.sleep(0.5)

        # --- C: LOGIN METHODE 1 (ARTEMIS HANDSHAKE) ---
        logger.info("Versuche Methode 1: Artemis Handshake...")
        token_bytes = ARTEMIS_TOKEN.encode('ascii') + b'\x00'
        p1 = b'\xd1\x00\x00\x05' + b'ARTEMIS\x00' + b'\x02\x00\x00\x00' + b'\x04\x00\x01\x00'
        p1 += struct.pack('<I', len(token_bytes)) + token_bytes
        
        if UDPWorker._try_login(sock, UDPWorker.create_packet(p1), camera_addr):
            return True, sock, camera_addr

        # --- D: LOGIN METHODE 2 (JSON DIREKT) ---
        logger.info("Methode 1 fehlgeschlagen. Versuche Methode 2: JSON Login...")
        login_json = {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "needAudio": 0,
            "utcTime": int(time.time()),
            "supportHeartBeat": True
        }
        json_bytes = json.dumps(login_json).encode('utf-8')
        
        if UDPWorker._try_login(sock, UDPWorker.create_packet(json_bytes), camera_addr):
            return True, sock, camera_addr

        logger.error("❌ Alle Login-Methoden fehlgeschlagen.")
        return False, sock, camera_addr

    @staticmethod
    def _try_login(sock, packet, addr):
        for i in range(2):
            sock.sendto(packet, addr)
            try:
                data, _ = sock.recvfrom(2048)
                # Antwort beginnt meist mit F1 D0
                if data.startswith(b'\xf1\xd0'):
                    logger.info("✅ LOGIN ERFOLGREICH!")
                    return True
            except socket.timeout:
                pass
            time.sleep(1)
        return False

# --- MAIN ---

async def main():
    logger.info("=== KJK Controller v3 ===")
    
    # WICHTIG: Stelle sicher, dass die App am Handy wirklich AUS ist (Prozess gekillt)!
    
    await BLEWorker.wake_camera_blindly()
    
    if not WiFiWorker.wait_and_connect(WIFI_SSID, WIFI_PASS, WIFI_INTERFACE):
        return
        
    logger.info("Warte 5s auf Netzwerk-Stack...")
    await asyncio.sleep(5)
    
    success, sock, dest = UDPWorker.start_session()
    
    if success:
        logger.info("--- SESSION AKTIV ---")
        try:
            while True:
                await asyncio.sleep(3)
                logger.info("Ping...")
                sock.sendto(bytes.fromhex("f1e00000"), dest)
        except KeyboardInterrupt: pass
    
    sock.close()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
