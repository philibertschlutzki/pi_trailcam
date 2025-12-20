import asyncio
import logging
import socket
import struct
import json
import base64
import time
import subprocess
from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- KONFIGURATION ---

# 1. BLUETOOTH
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"
UUID_WRITE     = "00000002-0000-1000-8000-00805f9b34fb"
BLE_WAKEUP_BYTES = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# 2. WLAN
CAM_WIFI_SSID = "KJK_E0FF"
CAM_WIFI_PASS = "85087127"

# 3. PROTOKOLL (Artemis / UDP)
CAMERA_IP     = "192.168.43.1"
CAMERA_PORT   = 40611
AES_KEY_STR   = "a01bc23ed45fF56A"

# Magic Bytes & Packet Types
MAGIC_BYTE    = 0xF1
TYPE_LBCS     = 0x41  # Handshake / Hole Punching
TYPE_CMD      = 0xD0  # Artemis Command (Verschlüsselt)

# Logging Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("Artemis_Client")

# --- KLASSEN FÜR KOMMUNIKATION ---

class CryptoHandler:
    def __init__(self, key_str):
        self.key = key_str.encode('utf-8')
        # AES im ECB Modus (Electronic Codebook) - Standard für diese Kameras
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def encrypt_json(self, json_obj):
        """Dict -> JSON String -> Padding -> AES Encrypt -> Base64"""
        # Compact JSON (keine Leerzeichen) für konsistente Verschlüsselung
        json_str = json.dumps(json_obj, separators=(',', ':'))
        data_bytes = json_str.encode('utf-8')
        
        # Padding (PKCS7 Standard)
        padded_data = pad(data_bytes, AES.block_size)
        
        # Verschlüsseln
        encrypted = self.cipher.encrypt(padded_data)
        
        # Base64 Kodieren
        return base64.b64encode(encrypted)

    def decrypt_payload(self, b64_bytes):
        """Base64 -> AES Decrypt -> Unpad -> JSON Dict"""
        try:
            encrypted_bytes = base64.b64decode(b64_bytes)
            decrypted_padded = self.cipher.decrypt(encrypted_bytes)
            decrypted_data = unpad(decrypted_padded, AES.block_size)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            logger.error(f"Decryption Error: {e}")
            return None

class PacketBuilder:
    def __init__(self, crypto):
        self.crypto = crypto
        self.seq_id = 1

    def build_lbcs_packet(self):
        """
        Baut das Handshake Paket (Typ 0x41).
        Payload aus Log: "LBCS" + Padding + "CCCJJ"
        """
        payload = bytes.fromhex("4c42435300000000000000004343434a4a000000")
        length = len(payload)
        # Header: F1 [Type] [Length BigEndian]
        header = struct.pack('>BBH', MAGIC_BYTE, TYPE_LBCS, length)
        return header + payload

    def build_artemis_cmd(self, cmd_dict):
        """
        Baut das verschlüsselte Artemis Paket (Typ 0xD0).
        Struktur: Header -> 'ARTEMIS\0' -> Meta -> Base64(Encrypted JSON)
        """
        # 1. Payload verschlüsseln
        encrypted_b64 = self.crypto.encrypt_json(cmd_dict)
        
        # 2. Artemis Header bauen
        artemis_sig = b'ARTEMIS\0'
        version = 2
        seq = self.seq_id
        data_len = len(encrypted_b64)
        self.seq_id += 1
        
        # Metadaten (Little Endian: Version, Seq, Length)
        meta = struct.pack('<III', version, seq, data_len)
        
        full_payload = artemis_sig + meta + encrypted_b64
        
        # 3. UDP Header drumherum (Big Endian)
        udp_len = len(full_payload)
        udp_header = struct.pack('>BBH', MAGIC_BYTE, TYPE_CMD, udp_len)
        
        return udp_header + full_payload

# --- WORKER KLASSEN (BLE & WIFI) ---

class BLEWorker:
    @staticmethod
    async def wake_camera(retries=3):
        for attempt in range(1, retries + 1):
            logger.info(f">>> SCHRITT 1: BLE Wakeup (Versuch {attempt})...")
            
            device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=8.0)
            if not device:
                logger.warning("BLE Gerät nicht gefunden (Evtl. schon im WiFi Modus?)")
                if attempt > 1: return True # Vermutlich schon an
                continue 

            try:
                async with BleakClient(device, timeout=15.0) as client:
                    logger.info("BLE verbunden! Sende Magic Bytes...")
                    await client.write_gatt_char(UUID_WRITE, BLE_WAKEUP_BYTES, response=True)
                    logger.info("BLE Befehl akzeptiert.")
                    return True
            except Exception as e:
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

# --- UDP PROTOKOLL LOGIK ---

class ProtocolWorker:
    def __init__(self):
        self.crypto = CryptoHandler(AES_KEY_STR)
        self.builder = PacketBuilder(self.crypto)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)

    async def listener(self):
        """Hört permanent auf UDP Pakete"""
        logger.info("🎧 UDP Listener aktiv...")
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                if len(data) > 4:
                    magic, ptype, length = struct.unpack('>BBH', data[:4])
                    payload = data[4:]

                    # 0x42 ist die Antwort auf LBCS (Handshake)
                    if ptype == 0x42:
                        pass # Ping Pong ignorieren

                    # 0xD0 ist eine Command Antwort
                    elif ptype == TYPE_CMD:
                        if payload.startswith(b'ARTEMIS\0'):
                            # Header (20 Bytes) überspringen
                            # Sig(8) + Ver(4) + Seq(4) + Len(4)
                            encrypted_data = payload[20:]
                            
                            # Entschlüsseln
                            resp = self.crypto.decrypt_payload(encrypted_data)
                            if resp:
                                logger.info(f"📩 ENTSCHLÜSSELT: {json.dumps(resp)}")
                                
                                if resp.get("cmdId") == 0 and resp.get("result") == 0:
                                    logger.info("🚀 LOGIN ERFOLGREICH BESTÄTIGT!")
                            else:
                                logger.warning("Payload konnte nicht entschlüsselt werden.")
                        else:
                            logger.info(f"Unbekanntes 0xD0 Paket: {data.hex()}")

            except BlockingIOError:
                await asyncio.sleep(0.01)
            except Exception as e:
                logger.error(f"Listener Error: {e}")
                await asyncio.sleep(1)

    async def run_session(self):
        logger.info(f">>> SCHRITT 3: UDP Session an {CAMERA_IP}:{CAMERA_PORT}")
        
        # Listener Task starten
        asyncio.create_task(self.listener())

        # 1. LBCS Handshake (Verbindung "lochen")
        logger.info("Sende LBCS Handshake...")
        lbcs_pkt = self.builder.build_lbcs_packet()
        for _ in range(5):
            self.sock.sendto(lbcs_pkt, (CAMERA_IP, CAMERA_PORT))
            await asyncio.sleep(0.2)

        # 2. Verschlüsselten Login senden
        login_cmd = {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "needAudio": 0,
            "utcTime": int(time.time()),
            "supportHeartBeat": True,
            "appType": "android"
        }
        
        logger.info("Sende verschlüsselten Login...")
        login_pkt = self.builder.build_artemis_cmd(login_cmd)
        self.sock.sendto(login_pkt, (CAMERA_IP, CAMERA_PORT))

        # 3. Heartbeat Loop
        logger.info("Starte Heartbeat Loop...")
        hb_cmd = {"cmdId": 259}
        
        try:
            while True:
                await asyncio.sleep(2)
                
                # Heartbeat senden
                hb_pkt = self.builder.build_artemis_cmd(hb_cmd)
                self.sock.sendto(hb_pkt, (CAMERA_IP, CAMERA_PORT))
                
                # Gelegentlich LBCS senden (macht die App auch)
                self.sock.sendto(lbcs_pkt, (CAMERA_IP, CAMERA_PORT))
                
        except asyncio.CancelledError:
            logger.info("Session beendet.")

# --- MAIN ---

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

    # 2. Protokoll starten
    logger.info("Warte 5s auf stabile Netzwerkverbindung...")
    await asyncio.sleep(5)
    
    worker = ProtocolWorker()
    await worker.run_session()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
