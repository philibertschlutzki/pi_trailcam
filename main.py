import asyncio
import logging
import sys
import socket
import json
import struct
import subprocess
from bleak import BleakScanner, BleakClient

# --- KONFIGURATION ---
# WiFi Daten der Kamera (vom Aufkleber oder App)
CAM_WIFI_SSID = "KJK_E0FF" 
CAM_WIFI_PASS = "85087127"  # Falls unbekannt, meist 12345678

# Neue Erkenntnisse aus 2025-12-19log.txt
CAMERA_IP = "192.168.43.1"   # Korrigierte IP
CAMERA_PORT = 40611          # Korrigierter Port
BLE_WAKEUP_BYTES = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# UUIDs (Bleiben gleich, da Standard)
UUID_SERVICE = "0000ffe0-0000-1000-8000-00805f9b34fb"
UUID_WRITE   = "0000ffe1-0000-1000-8000-00805f9b34fb"
UUID_NOTIFY  = "0000ffe2-0000-1000-8000-00805f9b34fb"

# Logging Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("KJK_Controller")

class BLEWorker:
    @staticmethod
    async def wake_camera():
        logger.info(">>> SCHRITT 1: BLE Wakeup...")
        device = await BleakScanner.find_device_by_filter(
            lambda d, ad: d.name and ("KJK" in d.name or "Trail" in d.name),
            timeout=15.0
        )
        if not device:
            logger.error("❌ Kamera nicht via Bluetooth gefunden.")
            return False

        logger.info(f"Gerät gefunden: {device.name} ({device.address})")
        async with BleakClient(device) as client:
            logger.info("BLE verbunden! Sende Magic Bytes...")
            await client.write_gatt_char(UUID_WRITE, BLE_WAKEUP_BYTES, response=True)
            logger.info(f"Gesendet: {BLE_WAKEUP_BYTES.hex()}")
            await asyncio.sleep(2) # Kurz warten
            logger.info("Trenne BLE Verbindung.")
        return True

class WiFiWorker:
    @staticmethod
    def connect_nmcli(ssid, password):
        logger.info(f">>> SCHRITT 2: Verbinde WLAN {ssid}...")
        # Scan erzwingen
        subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], capture_output=True)
        # Verbinden
        cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", password]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            logger.info("✅ WLAN verbunden!")
            return True
        else:
            if "already connected" in proc.stderr:
                logger.info("WLAN war bereits verbunden.")
                return True
            logger.error(f"❌ WLAN Fehler: {proc.stderr}")
            return False

class ProtocolWorker:
    @staticmethod
    def send_json_command(sock, command_dict):
        """Hilfsfunktion: Verpackt JSON in das Protokollformat"""
        json_str = json.dumps(command_dict)
        json_bytes = json_str.encode('utf-8')
        
        # Länge des Pakets berechnen (Oft 4 Byte Header + Daten)
        # Wir probieren erst Senden ohne Header (Raw JSON), da das Log 'Login cmd:{...}' zeigt.
        # Falls das nicht geht, aktivieren wir den Header unten.
        
        # OPTION A: Raw JSON (Wie im Log sichtbar)
        packet = json_bytes
        
        # OPTION B: Mit 4-Byte Länge-Header (üblich bei TCP)
        # packet = struct.pack('<I', len(json_bytes)) + json_bytes 

        logger.info(f"Sende: {json_str}")
        sock.sendall(packet)

    @staticmethod
    def run_session():
        logger.info(f">>> SCHRITT 3: TCP Verbindung zu {CAMERA_IP}:{CAMERA_PORT}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)

        try:
            sock.connect((CAMERA_IP, CAMERA_PORT))
            logger.info("✅ Socket verbunden!")
            
            # --- LOGIN ---
            # Exakt kopiert aus Log 
            login_cmd = {
                "cmdId": 0,
                "usrName": "admin",
                "password": "admin",
                "needVideo": 0,
                "needAudio": 0,
                "utcTime": 1766170701, # Zeitstempel ist egal
                "supportHeartBeat": True
            }
            
            ProtocolWorker.send_json_command(sock, login_cmd)
            
            # Antwort lesen
            response = sock.recv(4096)
            logger.info(f"Antwort empfangen ({len(response)} Bytes):")
            try:
                # Versuche Antwort als JSON zu parsen
                resp_str = response.decode('utf-8', errors='ignore')
                logger.info(f"RAW: {resp_str}")
                if "result\":0" in resp_str:
                    logger.info("🎉 LOGIN ERFOLGREICH!")
                else:
                    logger.warning("Login Antwort sieht komisch aus.")
            except:
                logger.info(f"HEX: {response.hex()}")

            # --- HEARTBEAT LOOP ---
            while True:
                time.sleep(3)
                # Heartbeat oder Statusabfrage senden, um Verbindung zu halten
                # Log zeigt cmdId 525 oder 259 als Heartbeats
                # ProtocolWorker.send_json_command(sock, {"cmdId": 525}) 
                pass 

        except Exception as e:
            logger.error(f"❌ Fehler: {e}")
        finally:
            sock.close()

async def main():
    # 1. BLE
    if not await BLEWorker.wake_camera():
        return
    
    # 2. WLAN (Warte kurz bis Kamera AP da ist)
    await asyncio.sleep(5)
    if not WiFiWorker.connect_nmcli(CAM_WIFI_SSID, CAM_WIFI_PASS):
        return

    # 3. Protokoll
    logger.info("Warte 5s auf DHCP...")
    await asyncio.sleep(5)
    ProtocolWorker.run_session()

if __name__ == "__main__":
    import time
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
