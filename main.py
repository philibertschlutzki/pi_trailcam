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

# 1. BLUETOOTH (MAC aus deinem Log)
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"  
UUID_WRITE     = "00000002-0000-1000-8000-00805f9b34fb"
BLE_WAKEUP_BYTES = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# 2. WLAN (Aus Log bestätigt)
CAM_WIFI_SSID = "KJK_E0FF" 
CAM_WIFI_PASS = "85087127"

# 3. PROTOKOLL (UDP P2P / Artemis)
CAMERA_IP     = "192.168.43.1"
CAMERA_PORT   = 40611

# Magic Bytes & Packet Types
MAGIC_BYTE    = 0xF1
TYPE_WAKEUP   = 0xE1
TYPE_LOGIN    = 0xD0
TYPE_HEARTBEAT= 0xD0 # Oft gleich wie Login/Command für JSON Payloads

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("KJK_Final")

class PacketBuilder:
    @staticmethod
    def build(packet_type, payload_bytes):
        """
        Erstellt ein Artemis-Paket:
        Header: [Magic F1] [Type 1B] [Length 2B BigEndian]
        Body:   [Payload]
        """
        length = len(payload_bytes)
        # struct.pack: B=unsigned char (1 byte), H=unsigned short (2 bytes)
        # > bedeutet Big Endian (Netzwerk-Byte-Order)
        header = struct.pack('>BBH', MAGIC_BYTE, packet_type, length)
        return header + payload_bytes

class BLEWorker:
    @staticmethod
    async def wake_camera(retries=3):
        for attempt in range(1, retries + 1):
            logger.info(f">>> SCHRITT 1: BLE Wakeup (Versuch {attempt})...")
            
            # Kurzer Check ob Kamera da ist
            device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=8.0)
            if not device:
                logger.warning("BLE Gerät nicht gefunden (Evtl. schon im WiFi Modus?)")
                if attempt > 1: return False # Nach Scan-Fehler abbrechen oder weitermachen?
                continue 

            try:
                async with BleakClient(device, timeout=15.0) as client:
                    logger.info("BLE verbunden! Sende Magic Bytes...")
                    await client.write_gatt_char(UUID_WRITE, BLE_WAKEUP_BYTES, response=True)
                    logger.info("BLE Befehl akzeptiert.")
                    return True
            except Exception as e:
                # "Not connected" Fehler sind normal beim Umschalten auf WiFi
                logger.info(f"BLE Aktion beendet ({e}). Kamera sollte starten.")
                return True 
        return False

class WiFiWorker:
    @staticmethod
    def is_connected_to(ssid):
        try:
            res = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
            return ssid in res.stdout.strip()
        except:
            return False

    @staticmethod
    def connect_nmcli(ssid, password):
        logger.info(f">>> SCHRITT 2: Verbinde WLAN {ssid}...")
        
        # Verbindung bereinigen
        subprocess.run(["sudo", "nmcli", "connection", "delete", ssid], capture_output=True)
        # Scan triggern
        subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], capture_output=True)
        time.sleep(3)
        
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
    def run_session():
        logger.info(f">>> SCHRITT 3: UDP Session an {CAMERA_IP}:{CAMERA_PORT}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0) # Timeout für Empfang

        try:
            # 1. WAKE-UP / INIT (Das fehlende Puzzleteil!)
            # Paket: F1 E1 00 04 E1 00 00 01
            # Payload ist E1 00 00 01 (Inner Type + Seq?)
            wakeup_payload = bytes.fromhex("E1000001") 
            wakeup_packet = PacketBuilder.build(TYPE_WAKEUP, wakeup_payload)
            
            logger.info("Sende Wake-Up Paket (0xE1)...")
            # Wir senden es ein paar Mal, da UDP unzuverlässig ist
            for _ in range(3):
                sock.sendto(wakeup_packet, (CAMERA_IP, CAMERA_PORT))
                time.sleep(0.2)

            # 2. LOGIN (JSON verpackt in 0xD0)
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
            login_payload = json_str.encode('utf-8')
            login_packet = PacketBuilder.build(TYPE_LOGIN, login_payload)

            logger.info(f"Sende Login Paket (Länge: {len(login_packet)} Bytes)...")
            sock.sendto(login_packet, (CAMERA_IP, CAMERA_PORT))

            # 3. EMPFANGSSCHLEIFE
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    
                    # Header parsen (ersten 4 Bytes)
                    if len(data) >= 4:
                        magic, p_type, length = struct.unpack('>BBH', data[:4])
                        payload = data[4:]
                        
                        # Versuch, Payload als JSON zu lesen
                        try:
                            json_resp = json.loads(payload.decode('utf-8', errors='ignore'))
                            logger.info(f"📩 ANTWORT (JSON): {json_resp}")
                            
                            if json_resp.get("result") == 0:
                                logger.info("🎉 LOGIN ERFOLGREICH! Verbindung steht.")
                                # Hier könnte man den Stream starten oder Heartbeats senden
                                
                        except:
                            # Falls kein JSON, Hex anzeigen
                            logger.info(f"📩 ANTWORT (HEX): {data.hex()}")

                        # Heartbeat Logik (Keep-Alive)
                        # Wenn wir eine Antwort bekommen, senden wir einen Heartbeat hinterher
                        # cmdId 259 (Heartbeat) oder 525 (GetState)
                        time.sleep(2)
                        hb_cmd = {"cmdId": 259} 
                        hb_packet = PacketBuilder.build(TYPE_HEARTBEAT, json.dumps(hb_cmd).encode('utf-8'))
                        sock.sendto(hb_packet, (CAMERA_IP, CAMERA_PORT))
                        logger.info("💓 Heartbeat gesendet.")

                except socket.timeout:
                    logger.warning("Keine Antwort erhalten. Sende Login erneut...")
                    sock.sendto(login_packet, (CAMERA_IP, CAMERA_PORT))

        except KeyboardInterrupt:
            logger.info("Beende...")
        except Exception as e:
            logger.error(f"Fehler: {e}")
        finally:
            sock.close()

async def main():
    # 1. WLAN prüfen & BLE Wakeup
    if WiFiWorker.is_connected_to(CAM_WIFI_SSID):
        logger.info("WLAN bereits verbunden. Überspringe BLE.")
    else:
        # Versuche BLE Wakeup
        await BLEWorker.wake_camera()
        
        # Warte kurz auf WLAN Start der Kamera
        logger.info("Warte 10s auf Kamera-WLAN...")
        await asyncio.sleep(10)
        
        # Verbinde WLAN
        if not WiFiWorker.connect_nmcli(CAM_WIFI_SSID, CAM_WIFI_PASS):
            return

    # 2. Protokoll starten
    # Wichtig: Warten bis DHCP durch ist
    logger.info("Warte 5s auf stabile Netzwerkverbindung...")
    await asyncio.sleep(5)
    
    ProtocolWorker.run_session()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
