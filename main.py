import asyncio
import logging
import sys
import time
import struct
import socket
import subprocess
from bleak import BleakScanner, BleakClient

# --- KONFIGURATION ---
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"

# WLAN Zugangsdaten (Aus deinem Log bekannt)
WIFI_SSID = "KJK_E0FF"
WIFI_PASS = "85087127"
WIFI_INTERFACE = "wlan0" # Da du eth0 nutzt, zwingen wir wlan0

# UUIDs für KJK/TC100 Kamera
UUID_WRITE   = "00000002-0000-1000-8000-00805f9b34fb" 

# Der 8-Byte Wake-Up Befehl
CMD_WAKEUP = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# Der Statische UDP Token
ARTEMIS_TOKEN = "MzlB36X/IVo8ZzI5rG9j1w=="

# UDP Settings
CAMERA_IP = "192.168.43.1"
CAMERA_PORT = 40611        
LOCAL_PORT = 5085          

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("KJK")

# --- MODULES ---

class BLEWorker:
    @staticmethod
    async def wake_camera_blindly():
        """Sendet den Aufwachbefehl und ignoriert das Ergebnis."""
        logger.info(f"PHASE 1: BLE Wakeup ({CAMERA_BLE_MAC})...")
        
        device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=8.0)

        if not device:
            logger.warning("Kamera nicht per BLE gefunden (Evtl. schon WLAN an?). Wir machen weiter...")
            return False

        logger.info(f"Verbinde BLE...")
        try:
            async with BleakClient(device) as client:
                logger.info("Sende 'WiFi Start' Befehl (Fire & Forget)...")
                # Wir senden es, ignorieren aber Timeouts, da die Kamera oft einfach rebootet
                try:
                    await client.write_gatt_char(UUID_WRITE, CMD_WAKEUP, response=True)
                except Exception as e:
                    logger.debug(f"Write-Fehler (ignoriert): {e}")
                
                logger.info("Befehl gesendet. Trenne BLE...")
        except Exception as e:
            logger.warning(f"BLE Verbindungsproblem: {e}")
            
        return True

class WiFiWorker:
    @staticmethod
    def wait_and_connect(ssid, password, interface="wlan0"):
        """Sucht in einer Schleife nach dem WLAN und verbindet sich."""
        logger.info(f"PHASE 2: Suche nach WLAN '{ssid}' auf {interface}...")
        
        max_retries = 20 # 20 Versuche a 3 Sekunden = 60 Sekunden Timeout
        
        for i in range(max_retries):
            # 1. Scannen (erzwingt Update der Liste)
            subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan", "ifname", interface], capture_output=True)
            time.sleep(2) # Kurz warten
            
            # 2. Prüfen ob SSID sichtbar ist
            check = subprocess.run(
                ["nmcli", "-f", "SSID", "device", "wifi", "list", "ifname", interface], 
                capture_output=True, text=True
            )
            
            if ssid in check.stdout:
                logger.info(f"WLAN '{ssid}' gefunden! Verbinde...")
                
                # Verbinden
                cmd = [
                    "sudo", "nmcli", "device", "wifi", "connect", ssid, 
                    "password", password, "ifname", interface
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                
                if proc.returncode == 0:
                    logger.info("✅ WLAN erfolgreich verbunden!")
                    return True
                else:
                    logger.error(f"Verbindung fehlgeschlagen: {proc.stderr.strip()}")
            else:
                logger.info(f"Warte auf WLAN... (Versuch {i+1}/{max_retries})")
                
            time.sleep(1)
            
        return False

class UDPWorker:
    @staticmethod
    def start_session():
        """Führt den UDP Login durch."""
        logger.info("PHASE 3: UDP Login & Heartbeat...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('0.0.0.0', LOCAL_PORT))
        except Exception:
            pass # Egal, OS sucht Port aus
        
        sock.settimeout(3.0)
        dest = (CAMERA_IP, CAMERA_PORT)

        # 1. UDP Wakeup Pakete
        logger.info("Sende UDP Ping...")
        sock.sendto(bytes.fromhex("f1e00000"), dest)
        time.sleep(0.1)
        sock.sendto(bytes.fromhex("f1e10000"), dest)
        time.sleep(0.5)

        # 2. Login Packet bauen
        token_bytes = ARTEMIS_TOKEN.encode('ascii') + b'\x00'
        
        payload = b''
        payload += b'\xd1\x00\x00\x05'          # Cmd
        payload += b'ARTEMIS\x00'               # Protocol
        payload += b'\x02\x00\x00\x00'          # Ver
        payload += b'\x04\x00\x01\x00'          # Const
        payload += struct.pack('<I', len(token_bytes)) 
        payload += token_bytes                  

        header = struct.pack('>BBH', 0xF1, 0xD0, len(payload))
        login_packet = header + payload
        
        # Mehrfach senden, UDP ist unzuverlässig
        for _ in range(3):
            logger.info(f"Sende Login Token...")
            sock.sendto(login_packet, dest)
            try:
                data, addr = sock.recvfrom(1024)
                if data.startswith(b'\xf1\xd0'):
                    logger.info("✅ UDP LOGIN ERFOLGREICH!")
                    return True, sock
            except socket.timeout:
                pass
            time.sleep(1)
            
        logger.error("❌ Kein UDP Login möglich (Timeout).")
        return False, sock

# --- MAIN WORKFLOW ---

async def main():
    logger.info("=== KJK Controller (ETH0 Mode) ===")

    # 1. BLE "Anstupsen"
    await BLEWorker.wake_camera_blindly()

    # 2. Auf WLAN warten (Polling Loop)
    if not WiFiWorker.wait_and_connect(WIFI_SSID, WIFI_PASS, WIFI_INTERFACE):
        logger.error("Abbruch: WLAN konnte nicht verbunden werden.")
        return

    # 3. IP Adresse abwarten (DHCP)
    logger.info("Warte 5s auf DHCP...")
    await asyncio.sleep(5)

    # 4. UDP Session
    success, sock = UDPWorker.start_session()
    
    if success:
        logger.info("--- KAMERA IST VERBUNDEN UND BEREIT ---")
        logger.info("Sende Heartbeats (Strg+C zum Beenden)...")
        try:
            while True:
                await asyncio.sleep(2)
                # Heartbeat Paket (Typ E0)
                sock.sendto(bytes.fromhex("f1e00000"), (CAMERA_IP, CAMERA_PORT))
                # Optional: Hier weitere Befehle einfügen
        except KeyboardInterrupt:
            pass
    
    sock.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
