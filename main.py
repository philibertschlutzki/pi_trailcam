import asyncio
import logging
import sys
import socket
import json
import subprocess
from bleak import BleakScanner, BleakClient

# --- KONFIGURATION ---

# 1. BLUETOOTH (Angepasst an deinen Scan!)
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"  

# Die neuen UUIDs aus deinem Scan-Ergebnis:
UUID_WRITE  = "00000002-0000-1000-8000-00805f9b34fb"
UUID_NOTIFY = "00000003-0000-1000-8000-00805f9b34fb"

# Magic Bytes (Bleiben gleich)
BLE_WAKEUP_BYTES = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# 2. WLAN (Aus Log bestätigt)
CAM_WIFI_SSID = "KJK_E0FF" 
CAM_WIFI_PASS = "85087127"

# 3. TCP VERBINDUNG (Aus Log bestätigt)
CAMERA_IP = "192.168.43.1"
CAMERA_PORT = 40611

# Logging Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("KJK_Controller")

class BLEWorker:
    @staticmethod
    async def wake_camera(retries=3):
        """Versucht mehrfach, die Kamera per BLE zu wecken."""
        for attempt in range(1, retries + 1):
            logger.info(f">>> SCHRITT 1: BLE Wakeup (Versuch {attempt}/{retries})...")
            
            device = None
            try:
                # Wir suchen direkt nach der MAC, das ist am schnellsten
                device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=15.0)
            except Exception as e:
                logger.warning(f"Scan Fehler: {e}")

            if not device:
                logger.warning("Kein Gerät gefunden. Ist die Kamera an?")
                continue

            logger.info(f"Gerät gefunden: {device.name} ({device.address})")
            
            try:
                async with BleakClient(device, timeout=20.0) as client:
                    if not client.is_connected:
                        logger.warning("Konnte nicht verbinden.")
                        continue
                        
                    logger.info(f"BLE verbunden! Schreibe auf {UUID_WRITE}...")
                    
                    # Sende die Magic Bytes
                    await client.write_gatt_char(UUID_WRITE, BLE_WAKEUP_BYTES, response=True)
                    logger.info(f"Gesendet: {BLE_WAKEUP_BYTES.hex()}")
                    
                    logger.info("Befehl akzeptiert. Trenne Verbindung...")
                    await asyncio.sleep(2)
                    return True # Erfolg

            except Exception as e:
                logger.error(f"❌ BLE Fehler: {e}")
                # Kurze Pause vor dem nächsten Versuch
                await asyncio.sleep(3)
        
        return False

class WiFiWorker:
    @staticmethod
    def connect_nmcli(ssid, password):
        logger.info(f">>> SCHRITT 2: Verbinde WLAN {ssid}...")
        
        # Scan erzwingen, damit der Pi das Netz sieht
        subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], capture_output=True)
        # Kurze Wartezeit für Scan-Ergebnisse
        import time
        time.sleep(3) 
        
        # Verbinden
        cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", password]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        
        if proc.returncode == 0:
            logger.info("✅ WLAN verbunden!")
            return True
        elif "already connected" in proc.stderr or "successfully activated" in proc.stdout:
            logger.info("✅ WLAN war bereits verbunden.")
            return True
        else:
            logger.error(f"❌ WLAN Fehler: {proc.stderr.strip()}")
            return False

class ProtocolWorker:
    @staticmethod
    def send_json_command(sock, command_dict):
        json_str = json.dumps(command_dict)
        json_bytes = json_str.encode('utf-8')
        logger.info(f"Sende: {json_str}")
        try:
            sock.sendall(json_bytes)
            return True
        except Exception as e:
            logger.error(f"Sendefehler: {e}")
            return False

    @staticmethod
    def run_session():
        logger.info(f">>> SCHRITT 3: TCP Verbindung zu {CAMERA_IP}:{CAMERA_PORT}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0) 

        try:
            sock.connect((CAMERA_IP, CAMERA_PORT))
            logger.info("✅ Socket verbunden! Sende Login...")
            
            # Login Befehl (JSON)
            login_cmd = {
                "cmdId": 0,
                "usrName": "admin",
                "password": "admin",
                "needVideo": 0,
                "needAudio": 0,
                "utcTime": 0,
                "supportHeartBeat": True
            }
            
            if not ProtocolWorker.send_json_command(sock, login_cmd):
                return

            # Antwort lesen
            response = sock.recv(4096)
            resp_str = response.decode('utf-8', errors='ignore')
            logger.info(f"Antwort: {resp_str}")

            if '"result":0' in resp_str or '"result": 0' in resp_str:
                logger.info("🎉 LOGIN ERFOLGREICH! Verbindung stabil.")
                
                # Heartbeat Loop (Alle 3 Sekunden)
                import time
                while True:
                    time.sleep(3)
                    # Laut Log reicht es oft, die Verbindung offen zu halten,
                    # oder man sendet einen Status-Request.
                    # Wir senden hier nichts, solange der Socket nicht stirbt.
                    # Falls die Verbindung abbricht, können wir {"cmdId": 259} senden.
            else:
                logger.warning("Login Antwort war nicht eindeutig 'Success'.")

        except Exception as e:
            logger.error(f"❌ TCP Fehler: {e}")
        finally:
            sock.close()

async def main():
    # 1. BLE Wakeup
    if not await BLEWorker.wake_camera():
        logger.error("Abbruch: Konnte Kamera nicht wecken.")
        return
    
    # 2. WLAN
    # Wir geben der Kamera 8 Sekunden, um den AP zu starten
    logger.info("Warte 8s auf Kamera-WLAN...")
    await asyncio.sleep(8)
    
    if not WiFiWorker.connect_nmcli(CAM_WIFI_SSID, CAM_WIFI_PASS):
        return

    # 3. TCP Session
    logger.info("Warte 5s auf Netzwerk-Konfiguration...")
    await asyncio.sleep(5)
    ProtocolWorker.run_session()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
