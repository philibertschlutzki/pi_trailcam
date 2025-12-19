import asyncio
import logging
import sys
import socket
import json
import subprocess
from bleak import BleakScanner, BleakClient

# --- KONFIGURATION ---

# 1. BLUETOOTH
# MAC aus deinem Log: C6:1E:0D:E0:32:E8
# Falls es Probleme gibt, setze dies auf None, damit er neu scannt.
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"  
UUID_WRITE     = "0000ffe1-0000-1000-8000-00805f9b34fb"
BLE_WAKEUP_BYTES = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# 2. WLAN (Gefunden in 2025-12-19log.txt Zeile 4481)
CAM_WIFI_SSID = "KJK_E0FF" 
CAM_WIFI_PASS = "85087127"  # Das korrekte Passwort aus dem Log!

# 3. PROTOKOLL (Gefunden in 2025-12-19log.txt Zeile 4412)
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
            if CAMERA_BLE_MAC:
                try:
                    device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=10.0)
                except Exception:
                    pass
            
            if not device:
                logger.info("Suche via Scan nach 'KJK' oder 'Trail'...")
                device = await BleakScanner.find_device_by_filter(
                    lambda d, ad: d.name and ("KJK" in d.name or "Trail" in d.name or "TC100" in d.name),
                    timeout=10.0
                )

            if not device:
                logger.warning("Kein Gerät gefunden. Ist Bluetooth am Handy AUS?")
                continue

            logger.info(f"Gerät gefunden: {device.name} ({device.address})")
            
            try:
                async with BleakClient(device, timeout=15.0) as client:
                    if not client.is_connected:
                        logger.warning("Konnte nicht verbinden.")
                        continue
                        
                    logger.info("BLE verbunden! Sende Magic Bytes...")
                    # Schreiben mit Response=True um sicherzugehen, dass es ankam
                    await client.write_gatt_char(UUID_WRITE, BLE_WAKEUP_BYTES, response=True)
                    logger.info(f"Gesendet: {BLE_WAKEUP_BYTES.hex()}")
                    
                    logger.info("Warte kurz und trenne Verbindung...")
                    await asyncio.sleep(2)
                    return True # Erfolg

            except Exception as e:
                logger.error(f"❌ BLE Fehler: {repr(e)}") # repr(e) zeigt den genauen Fehlertyp
                await asyncio.sleep(2)
        
        return False

class WiFiWorker:
    @staticmethod
    def connect_nmcli(ssid, password):
        logger.info(f">>> SCHRITT 2: Verbinde WLAN {ssid} mit PW {password}...")
        
        # WLAN Interface neustarten (hilft oft beim Pi)
        # subprocess.run(["sudo", "ifconfig", "wlan0", "down"], capture_output=True)
        # time.sleep(1)
        # subprocess.run(["sudo", "ifconfig", "wlan0", "up"], capture_output=True)
        
        # Scan erzwingen
        subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], capture_output=True)
        await_time = 5
        logger.info(f"Warte {await_time}s auf Scan-Ergebnisse...")
        
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
            
            # Login Paket (JSON) - exakt wie im Log
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

            response = sock.recv(4096)
            resp_str = response.decode('utf-8', errors='ignore')
            logger.info(f"Antwort: {resp_str}")

            if '"result":0' in resp_str or '"result": 0' in resp_str:
                logger.info("🎉 LOGIN ERFOLGREICH! Verbindung steht.")
                
                # Heartbeat Loop
                import time
                while True:
                    time.sleep(3)
                    # Heartbeat (cmdId 259 oder 525 laut Log)
                    # Sende einfach leeres JSON oder Heartbeat
                    # ProtocolWorker.send_json_command(sock, {"cmdId": 525})
            else:
                logger.warning("Login Antwort war nicht 'Success'.")

        except Exception as e:
            logger.error(f"❌ TCP Protokoll Fehler: {e}")
        finally:
            sock.close()

async def main():
    # 1. BLE Wakeup (mit Retries)
    if not await BLEWorker.wake_camera():
        logger.error("Konnte Kamera nicht per Bluetooth wecken. Abbruch.")
        return
    
    # 2. WLAN (Zeit lassen zum Starten des APs)
    logger.info("Warte 10s, bis Kamera-WLAN hochgefahren ist...")
    await asyncio.sleep(10)
    
    if not WiFiWorker.connect_nmcli(CAM_WIFI_SSID, CAM_WIFI_PASS):
        return

    # 3. TCP Session
    logger.info("Warte 5s auf DHCP/Netzwerk...")
    await asyncio.sleep(5)
    ProtocolWorker.run_session()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
