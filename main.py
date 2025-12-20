import asyncio
import logging
import sys
import socket
import json
import struct
import subprocess
import time
from bleak import BleakScanner, BleakClient

# --- KONFIGURATION ---

# 1. BLUETOOTH
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"
UUID_WRITE     = "00000002-0000-1000-8000-00805f9b34fb"
BLE_WAKEUP_BYTES = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# 2. WLAN
CAM_WIFI_SSID = "KJK_E0FF"
CAM_WIFI_PASS = "85087127"

# 3. PROTOKOLL
CAMERA_IP     = "192.168.43.1"
CAMERA_PORT   = 40611

# Magic Bytes & Packet Types
MAGIC_BYTE    = 0xF1
TYPE_WAKEUP   = 0xE1
TYPE_LOGIN    = 0xD0
TYPE_HEARTBEAT= 0xD0

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("KJK_Final")

class PacketBuilder:
    @staticmethod
    def build(packet_type, payload_bytes):
        """Erstellt ein Artemis-Paket: [Magic F1] [Type 1B] [Length 2B] [Payload]"""
        length = len(payload_bytes)
        header = struct.pack('>BBH', MAGIC_BYTE, packet_type, length)
        return header + payload_bytes

class BLEWorker:
    @staticmethod
    async def wake_camera(retries=3):
        for attempt in range(1, retries + 1):
            logger.info(f">>> SCHRITT 1: BLE Wakeup (Versuch {attempt})...")
            try:
                device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=10.0)
                if not device:
                    logger.warning("Kamera via BLE nicht gefunden (evtl. schon an?)")
                    return True # Wir gehen davon aus, dass sie an ist

                async with BleakClient(device, timeout=15.0) as client:
                    logger.info("BLE verbunden! Sende Magic Bytes...")
                    await client.write_gatt_char(UUID_WRITE, BLE_WAKEUP_BYTES, response=True)
                    logger.info("BLE Befehl akzeptiert.")
                    return True
            except Exception as e:
                logger.warning(f"BLE Fehler (oft normal bei WiFi-Start): {e}")
                return True
        return False

class WiFiWorker:
    @staticmethod
    def is_connected_to(ssid):
        try:
            # Checkt die aktuelle SSID
            res = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
            return ssid in res.stdout.strip()
        except:
            return False

    @staticmethod
    def ping_camera(ip):
        """Prüft, ob die Kamera per Ping erreichbar ist."""
        logger.info(f"Pinge Kamera {ip}...")
        try:
            # -c 1 = ein Paket, -W 1 = 1 Sekunde Timeout
            res = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True)
            return res.returncode == 0
        except:
            return False

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
    def run_session():
        logger.info(f">>> SCHRITT 3: UDP Session an {CAMERA_IP}:{CAMERA_PORT}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Broadcast erlauben
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind(('0.0.0.0', 0)) # Binde an freien Port
        except Exception as e:
            logger.error(f"Socket Bind Fehler: {e}")

        sock.settimeout(2.0) # 2 Sekunden warten auf Antwort

        # --- PHASE A: HANDSHAKE / WAKEUP ---
        # Wir senden das Wakeup-Paket so lange, bis eine Antwort kommt.
        # Payload: E1 00 00 01 (Inner Type + Seq)
        wakeup_payload = bytes.fromhex("E1000001")
        wakeup_packet = PacketBuilder.build(TYPE_WAKEUP, wakeup_payload)

        handshake_success = False
        max_attempts = 15 # Versuche für 30 Sekunden

        logger.info("Starte Handshake-Loop (0xE1)...")

        for i in range(max_attempts):
            try:
                # Sende an Unicast IP
                sock.sendto(wakeup_packet, (CAMERA_IP, CAMERA_PORT))
                # Optional: Sende auch an Broadcast (Endung .255), falls IP noch nicht stabil
                broadcast_ip = CAMERA_IP.rsplit('.', 1)[0] + ".255"
                sock.sendto(wakeup_packet, (broadcast_ip, CAMERA_PORT))

                # Warte auf Antwort
                data, addr = sock.recvfrom(4096)
                logger.info(f"✅ Handshake Antwort von {addr}: {data.hex()}")
                handshake_success = True
                break
            except socket.timeout:
                logger.info(f"Handshake Versuch {i+1}/{max_attempts}: Keine Antwort...")
            except Exception as e:
                logger.error(f"Fehler beim Senden: {e}")
                time.sleep(1)

        if not handshake_success:
            logger.error("❌ Kamera hat nicht auf Wake-Up geantwortet. Abbruch.")
            return

        # --- PHASE B: LOGIN ---
        logger.info("Handshake OK. Sende Login...")

        login_cmd = {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "needAudio": 0,
            "utcTime": int(time.time()),
            "supportHeartBeat": True
        }
        json_str = json.dumps(login_cmd)
        login_packet = PacketBuilder.build(TYPE_LOGIN, json_str.encode('utf-8'))

        try:
            sock.sendto(login_packet, (CAMERA_IP, CAMERA_PORT))

            # Warte auf Login-Bestätigung
            data, addr = sock.recvfrom(4096)

            # Header entfernen (4 Bytes) und Payload lesen
            if len(data) > 4:
                payload = data[4:]
                try:
                    resp_json = json.loads(payload.decode('utf-8', errors='ignore'))
                    logger.info(f"📩 LOGIN ANTWORT: {resp_json}")

                    if resp_json.get("result") == 0:
                        logger.info("🎉🎉🎉 LOGIN ERFOLGREICH! VERBINDUNG STEHT! 🎉🎉🎉")

                        # --- HEARTBEAT LOOP ---
                        while True:
                            time.sleep(3)
                            logger.info("Sende Heartbeat...")
                            hb_packet = PacketBuilder.build(TYPE_HEARTBEAT, json.dumps({"cmdId": 259}).encode('utf-8'))
                            sock.sendto(hb_packet, (CAMERA_IP, CAMERA_PORT))

                            try:
                                hb_data, _ = sock.recvfrom(4096)
                                # logger.info(f"Heartbeat Echo: {len(hb_data)} Bytes")
                            except socket.timeout:
                                pass # Heartbeats können auch mal verloren gehen
                except:
                    logger.info(f"Antwort (Hex): {data.hex()}")

        except Exception as e:
            logger.error(f"Login Fehler: {e}")
        finally:
            sock.close()

async def main():
    # 1. WLAN prüfen & BLE Wakeup
    if WiFiWorker.is_connected_to(CAM_WIFI_SSID):
        logger.info("WLAN bereits verbunden. Überspringe BLE.")
    else:
        await BLEWorker.wake_camera()
        logger.info("Warte 10s auf Kamera-WLAN...")
        await asyncio.sleep(10)

        if not WiFiWorker.connect_nmcli(CAM_WIFI_SSID, CAM_WIFI_PASS):
            return

    # 2. Ping Check (Wichtig für Diagnose)
    logger.info("Prüfe Netzwerk-Erreichbarkeit...")
    for _ in range(10):
        if WiFiWorker.ping_camera(CAMERA_IP):
            logger.info("✅ Kamera ist per Ping erreichbar!")
            break
        logger.info("Warte auf Ping...")
        time.sleep(1)

    # 3. Protokoll starten
    ProtocolWorker.run_session()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
