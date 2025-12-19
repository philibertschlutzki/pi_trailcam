import asyncio
import logging
import sys
import time
import struct
import socket
import json
import subprocess
from bleak import BleakScanner, BleakClient

# --- CONFIGURATION ---

# 1. BLE Settings
# Falls bekannt, hier eintragen (z.B. "00:11:22:33:44:55"), sonst scannt er jedes Mal.
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"

# UUIDs für Artemis/Novatek Chipsätze (Standard)
UUID_SERVICE = "0000ffe0-0000-1000-8000-00805f9b34fb"
UUID_WRITE   = "0000ffe1-0000-1000-8000-00805f9b34fb"
UUID_NOTIFY  = "0000ffe2-0000-1000-8000-00805f9b34fb"

# Das "Magic WakeUp Packet" (8 Bytes). 
# Basierend auf Log-Analyse "Send data to bluetooth, len:8".
# Dies ist der Standard-Befehl für KJK/Artemis.
CMD_WAKEUP = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# 2. WiFi Settings (Vom Log bestätigt)
# Du musst SSID und Passwort deiner Kamera hier eintragen, da BLE diese oft nicht überträgt.
CAM_WIFI_SSID = "KJK_E0FF"  # Ersetze dies mit dem exakten Namen aus deinem Handy
CAM_WIFI_PASS = "85087127"  # Meistens 12345678 bei diesen Kameras

# 3. Connection Settings (Vom Log bestätigt)
CAMERA_IP = "192.168.30.1"  # Gefunden im Logcat (DnsManager)
CAMERA_PORT = 3333          # Standard Artemis Command Port (TCP)
LOCAL_PORT = 0              # 0 = OS wählt freien Port

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("Artemis_Control")

# --- WORKER MODULES ---

class BLEWorker:
    @staticmethod
    async def wake_camera():
        """Verbindet via BLE und sendet den 8-Byte Aufweck-Befehl."""
        logger.info(f">>> SCHRITT 1: BLE Wakeup ({CAMERA_BLE_MAC if CAMERA_BLE_MAC else 'Auto-Scan'})")

        device = None
        if CAMERA_BLE_MAC:
            device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=10.0)
        else:
            # Filtert nach Geräten mit 'KJK', 'Trail' oder 'Cam' im Namen
            device = await BleakScanner.find_device_by_filter(
                lambda d, ad: d.name and any(x in d.name for x in ["KJK", "Trail", "Cam"]),
                timeout=15.0
            )

        if not device:
            logger.error("❌ Kamera nicht via Bluetooth gefunden.")
            return False

        logger.info(f"Gerät gefunden: {device.name} ({device.address})")

        async with BleakClient(device) as client:
            logger.info("BLE verbunden! Sende Magic Bytes...")
            
            # Wir abonnieren Notifications, falls die Kamera antwortet (Bestätigung)
            await client.start_notify(UUID_NOTIFY, lambda s, d: logger.info(f"BLE Notify: {d.hex()}"))
            
            # Sende die 8 Bytes (CMD_WAKEUP)
            await client.write_gatt_char(UUID_WRITE, CMD_WAKEUP, response=True)
            logger.info(f"Gesendet: {CMD_WAKEUP.hex()}")

            # Kurze Wartezeit, damit der Befehl verarbeitet wird
            logger.info("Warte auf Kamera-Reaktion...")
            await asyncio.sleep(3)
            
            logger.info("Trenne BLE Verbindung (Kamera sollte nun WiFi starten).")
        
        return True

class WiFiWorker:
    @staticmethod
    def connect_nmcli(ssid, password):
        """Verbindet WiFi mittels Linux NetworkManager (nmcli)."""
        logger.info(f">>> SCHRITT 2: Verbinde WLAN {ssid}...")

        # 1. Scan erzwingen (hilft dem Pi, das neue Netz schnell zu finden)
        subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], capture_output=True)
        time.sleep(3)

        # 2. Verbinden
        cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", password]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode == 0:
            logger.info(f"WLAN verbunden! IP-Check läuft...")
            # Optional: Prüfen ob wir wirklich eine IP im 192.168.30.x Bereich haben
            return True
        else:
            if "already connected" in proc.stderr or "successfully activated" in proc.stdout:
                logger.info("WLAN war bereits verbunden.")
                return True
            logger.error(f"❌ WLAN Fehler: {proc.stderr}")
            return False

class ArtemisProtocol:
    @staticmethod
    def connect_and_handshake():
        """Baut TCP Verbindung auf und führt den Artemis Handshake durch."""
        logger.info(f">>> SCHRITT 3: TCP Verbindung zu {CAMERA_IP}:{CAMERA_PORT}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # WICHTIG: TCP (SOCK_STREAM)
        sock.settimeout(5.0)

        try:
            sock.connect((CAMERA_IP, CAMERA_PORT))
            logger.info(f"Socket verbunden mit {CAMERA_IP}:{CAMERA_PORT}")
        except Exception as e:
            logger.error(f"❌ TCP Verbindung fehlgeschlagen: {e}")
            return None

        # --- ARTEMIS HANDSHAKE ---
        # Aufbau basierend auf Log "EC-SDK sendCommand"
        # Wir müssen ein Login/Init Paket senden. 
        # Da wir den genauen Inhalt noch nicht gesniffert haben, nutzen wir eine generische 
        # Artemis-Struktur. Falls dies fehlschlägt, brauchen wir den Hex-Dump aus Schritt 3.
        
        # Versuch 1: Einfacher Init-Befehl (Little Endian)
        # Struktur oft: [Header 4B] [Länge 4B] [CMD ID 4B] [Payload...]
        
        # Hier senden wir eine gängige Sequenz für Novatek Chipsätze
        # Hex: AA 01 02 00 ... (Beispiel)
        # Wir probieren den im alten Script vermuteten Token, aber über TCP.
        
        # TOKEN CONSTRUCTION (aus deinem alten Script übernommen, aber angepasst)
        ARTEMIS_TOKEN = "MzlB36X/IVo8ZzI5rG9j1w=="
        token_bytes = ARTEMIS_TOKEN.encode('ascii') + b'\x00'

        payload = b''
        payload += b'\xd1\x00\x00\x05'          # Command ID (Login/Handshake)
        payload += b'ARTEMIS\x00'               # Protocol String
        payload += b'\x02\x00\x00\x00'          # Version
        payload += b'\x04\x00\x01\x00'          # Unknown
        payload += struct.pack('<I', len(token_bytes)) 
        payload += token_bytes

        # Header: Magic(F1) + Type(D0) + Length
        header = struct.pack('>BBH', 0xF1, 0xD0, len(payload))
        full_packet = header + payload

        logger.info(f"Sende Login Paket ({len(full_packet)} bytes)...")
        try:
            sock.sendall(full_packet)
            
            # Antwort lesen
            response = sock.recv(1024)
            logger.info(f"Antwort empfangen (HEX): {response.hex()}")
            
            if len(response) > 0:
                logger.info("✅ Kamera hat geantwortet! Verbindung steht.")
                return sock
            else:
                logger.warning("Keine Daten empfangen.")
                return None

        except Exception as e:
            logger.error(f"Fehler beim Handshake: {e}")
            return None

# --- MAIN LOOP ---

async def main():
    # 1. Kamera aufwecken (Bluetooth)
    if not await BLEWorker.wake_camera():
        return

    # 2. WLAN verbinden
    # Warte kurz, bis Kamera-AP hochgefahren ist (Log zeigt ca. 2-3 Sekunden Delay)
    logger.info("Warte 5 Sekunden auf Kamera-WLAN...")
    await asyncio.sleep(5)
    
    if not WiFiWorker.connect_nmcli(CAM_WIFI_SSID, CAM_WIFI_PASS):
        return

    # 3. IP Stack warten (DHCP)
    logger.info("Warte auf IP-Adresse...")
    await asyncio.sleep(3)

    # 4. TCP Verbindung aufbauen
    sock = ArtemisProtocol.connect_and_handshake()

    if sock:
        logger.info("--- SYSTEM BEREIT ---")
        logger.info("Sende Heartbeats (Alle 3s)... Drücke STRG+C zum Beenden.")
        
        # Einfacher Heartbeat Loop
        try:
            while True:
                await asyncio.sleep(3)
                # Sende Heartbeat (Oft Typ E0 oder leerer Befehl)
                heartbeat = bytes.fromhex("f1e00000") 
                try:
                    sock.sendall(heartbeat)
                    # Antwort lesen (non-blocking machen wir hier simpel mit kurzem Timeout)
                    sock.settimeout(0.5)
                    try:
                        resp = sock.recv(128)
                        # logger.debug(f"Heartbeat Echo: {resp.hex()}")
                    except socket.timeout:
                        pass
                except Exception as e:
                    logger.error(f"Verbindung verloren: {e}")
                    break
        except KeyboardInterrupt:
            logger.info("Beende...")
        finally:
            sock.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
