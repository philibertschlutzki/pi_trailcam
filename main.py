import asyncio
import logging
import sys
import socket
import json
import subprocess
import time
from bleak import BleakScanner, BleakClient

# --- KONFIGURATION ---

# BLE (Deine MAC & UUIDs aus dem Scan)
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"  
UUID_WRITE     = "00000002-0000-1000-8000-00805f9b34fb"
UUID_NOTIFY    = "00000003-0000-1000-8000-00805f9b34fb"
BLE_WAKEUP     = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# WLAN
CAM_WIFI_SSID = "KJK_E0FF" 
CAM_WIFI_PASS = "85087127"

# TCP (Aus Log)
CAMERA_IP     = "192.168.43.1"
CAMERA_PORT   = 40611

# Logging Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("KJK_Control")

class BLEWorker:
    @staticmethod
    async def wake_camera(retries=3):
        for attempt in range(1, retries + 1):
            logger.info(f">>> SCHRITT 1: BLE Wakeup (Versuch {attempt})...")
            device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=10.0)
            
            if not device:
                logger.warning("Kamera nicht gefunden (Ist Bluetooth am Handy aus?)")
                continue

            try:
                async with BleakClient(device, timeout=15.0) as client:
                    logger.info("BLE verbunden! Sende Magic Bytes...")
                    await client.write_gatt_char(UUID_WRITE, BLE_WAKEUP, response=True)
                    logger.info("Befehl akzeptiert. Trenne...")
                    await asyncio.sleep(1)
                    return True
            except Exception as e:
                logger.error(f"BLE Fehler: {e}")
                await asyncio.sleep(2)
        return False

class WiFiWorker:
    @staticmethod
    def connect_nmcli(ssid, password):
        logger.info(f">>> SCHRITT 2: Verbinde WLAN {ssid}...")
        subprocess.run(["sudo", "nmcli", "connection", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], capture_output=True)
        time.sleep(3)
        
        cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", password]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        
        if proc.returncode == 0:
            logger.info("✅ WLAN verbunden!")
            return True
        else:
            logger.error(f"❌ WLAN Fehler: {proc.stderr.strip()}")
            return False

class ProtocolWorker:
    @staticmethod
    def wait_for_port(ip, port, timeout=60):
        """Wartet bis zu 60s, dass der Port TCP Connects annimmt."""
        logger.info(f"⏳ Warte auf Port {port} bei {ip} (Max {timeout}s)...")
        start_time = time.time()
        while time.time() - start_time < timeout:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                logger.info(f"✅ Port {port} ist OFFEN!")
                return True
            else:
                time.sleep(1)
                print(".", end="", flush=True)
        
        logger.error(f"\n❌ Timeout: Port {port} blieb geschlossen.")
        return False

    @staticmethod
    def run_session():
        if not ProtocolWorker.wait_for_port(CAMERA_IP, CAMERA_PORT):
            # Fallback: Port Scan, falls 40611 falsch ist
            logger.info("Starte Notfall-Port-Scan (Ports 3000-50000)...")
            for p in [3333, 8080, 80, 40611, 554]: # Schnellcheck
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)
                if sock.connect_ex((CAMERA_IP, p)) == 0:
                    logger.info(f"GEFUNDEN: Port {p} ist offen!")
                    # Hier könnte man weitermachen
                sock.close()
            return

        logger.info(f">>> SCHRITT 3: Login an {CAMERA_IP}:{CAMERA_PORT}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.connect((CAMERA_IP, CAMERA_PORT))
            
            # Login Payload (Exakt aus Log)
            login_cmd = {
                "cmdId": 0,
                "usrName": "admin",
                "password": "admin",
                "needVideo": 0,
                "needAudio": 0,
                "utcTime": 0,
                "supportHeartBeat": True
            }
            json_payload = json.dumps(login_cmd).encode('utf-8')
            
            logger.info(f"Sende Login ({len(json_payload)} bytes)...")
            sock.sendall(json_payload)
            
            response = sock.recv(4096)
            logger.info(f"Antwort: {response.decode('utf-8', errors='ignore')}")

            # Heartbeat Loop
            while True:
                time.sleep(3)
                # Keep-Alive senden?
                
        except Exception as e:
            logger.error(f"Protokoll-Fehler: {e}")
        finally:
            sock.close()

async def main():
    if not await BLEWorker.wake_camera():
        return
    
    # WLAN Connect
    logger.info("Warte 10s auf WLAN-Signal...")
    await asyncio.sleep(10)
    
    if not WiFiWorker.connect_nmcli(CAM_WIFI_SSID, CAM_WIFI_PASS):
        return

    # WICHTIG: DHCP braucht Zeit
    logger.info("Warte 5s auf IP-Adresse...")
    await asyncio.sleep(5)
    
    # Protokoll starten
    ProtocolWorker.run_session()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
