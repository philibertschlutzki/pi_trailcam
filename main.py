import asyncio
import logging
import sys
import socket
import json
import subprocess
import time
from bleak import BleakScanner, BleakClient

# --- KONFIGURATION ---

# BLE (MAC aus Log)
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"  
UUID_WRITE     = "00000002-0000-1000-8000-00805f9b34fb"
BLE_WAKEUP     = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# WLAN
CAM_WIFI_SSID = "KJK_E0FF" 
CAM_WIFI_PASS = "85087127"

# TCP
CAMERA_IP     = "192.168.43.1"
CAMERA_PORT   = 40611

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("KJK_Control")

class BLEWorker:
    @staticmethod
    async def wake_camera(retries=3):
        for attempt in range(1, retries + 1):
            logger.info(f">>> SCHRITT 1: BLE Wakeup (Versuch {attempt})...")
            
            # Kurzer Scan Check ob Gerät überhaupt da ist
            device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=8.0)
            
            if not device:
                logger.warning("BLE Gerät nicht gefunden (Kamera schon im WiFi Modus?)")
                # Wenn wir die Kamera per BLE nicht sehen, ist sie evtl schon an.
                # Wir geben hier nicht sofort auf, sondern lassen main() entscheiden.
                continue

            try:
                async with BleakClient(device, timeout=15.0) as client:
                    logger.info("BLE verbunden! Sende Magic Bytes...")
                    await client.write_gatt_char(UUID_WRITE, BLE_WAKEUP, response=True)
                    logger.info("Befehl akzeptiert.")
                    # Wir ignorieren Fehler beim Trennen, da die Kamera oft hart trennt
                    return True
            except Exception as e:
                # Ein Fehler NACH dem Senden ist oft kein echter Fehler, da die Kamera rebootet
                if "Befehl akzeptiert" in str(e): 
                    return True
                logger.error(f"BLE Fehler (oft normal beim Umschalten): {e}")
                await asyncio.sleep(2)
        return False

class WiFiWorker:
    @staticmethod
    def is_wifi_visible(ssid):
        """Prüft kurz, ob das WLAN schon sichtbar ist."""
        logger.info("Prüfe, ob Kamera-WLAN schon aktiv ist...")
        try:
            # Schneller Scan
            subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], capture_output=True)
            time.sleep(2)
            # Liste abrufen
            result = subprocess.run(["sudo", "nmcli", "-t", "-f", "SSID", "dev", "wifi"], capture_output=True, text=True)
            if ssid in result.stdout:
                logger.info(f"✅ WLAN '{ssid}' gefunden! Überspringe BLE.")
                return True
        except Exception:
            pass
        logger.info("WLAN noch nicht sichtbar.")
        return False

    @staticmethod
    def connect_nmcli(ssid, password):
        logger.info(f">>> SCHRITT 2: Verbinde WLAN {ssid}...")
        
        # Verbindungsprofil bereinigen (verhindert Key-Mgmt Fehler)
        subprocess.run(["sudo", "nmcli", "connection", "delete", ssid], capture_output=True)
        
        # Verbinden
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
        logger.info(f"⏳ Warte auf Port {port} bei {ip} (Max {timeout}s)...")
        start_time = time.time()
        while time.time() - start_time < timeout:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    logger.info(f"✅ Port {port} ist OFFEN!")
                    sock.close()
                    return True
            except:
                pass
            sock.close()
            time.sleep(1)
            print(".", end="", flush=True)
        print("")
        return False

    @staticmethod
    def run_session():
        # Warte, bis der Port wirklich da ist (verhindert Connection Refused)
        if not ProtocolWorker.wait_for_port(CAMERA_IP, CAMERA_PORT):
            logger.error("Kamera nicht erreichbar (Port zu).")
            return

        logger.info(f">>> SCHRITT 3: Login an {CAMERA_IP}:{CAMERA_PORT}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.connect((CAMERA_IP, CAMERA_PORT))
            
            # JSON Login (aus Log)
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
            
            logger.info(f"Sende Login...")
            sock.sendall(json_payload)
            
            response = sock.recv(4096)
            resp_text = response.decode('utf-8', errors='ignore')
            logger.info(f"Antwort: {resp_text}")

            if '"result":0' in resp_text or '"result": 0' in resp_text:
                logger.info("🎉 LOGIN ERFOLGREICH! Sende Heartbeats...")
                while True:
                    time.sleep(3)
                    # Optional: Heartbeat senden, falls nötig
            else:
                logger.warning("Login fehlgeschlagen?")

        except Exception as e:
            logger.error(f"Session Fehler: {e}")
        finally:
            sock.close()

async def main():
    # NEU: Prüfe zuerst WLAN. Nur wenn weg -> BLE Wakeup
    if WiFiWorker.is_wifi_visible(CAM_WIFI_SSID):
        logger.info("Kamera ist bereits wach.")
    else:
        if not await BLEWorker.wake_camera():
            logger.warning("BLE fehlgeschlagen oder übersprungen. Versuche trotzdem WLAN...")
    
    # WLAN Verbinden
    if not WiFiWorker.connect_nmcli(CAM_WIFI_SSID, CAM_WIFI_PASS):
        return

    # Warten auf DHCP
    logger.info("Warte 5s auf IP-Adresse...")
    await asyncio.sleep(5)
    
    # Protokoll
    ProtocolWorker.run_session()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
