import socket
import struct
import time
import json
import logging
import sys
import argparse
import subprocess
import asyncio
import base64
import os
from bleak import BleakScanner, BleakClient

# --- KONFIGURATION ---
DEFAULT_CAMERA_IP = "192.168.43.1"
DEFAULT_CAMERA_PORT = 40611
DEFAULT_WIFI_SSID = "KJK_E0FF"      # Deine SSID anpassen
DEFAULT_WIFI_PASS = "85087127"      # Dein Passwort anpassen
DEFAULT_BLE_MAC = "C6:1E:0D:E0:32:E8" # Deine MAC anpassen

# UUIDs und Magic Bytes für BLE Wakeup
BLE_UUID_WRITE = "00000002-0000-1000-8000-00805f9b34fb"
BLE_WAKEUP_BYTES = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# Login Token (aus deinem Log)
TEST_BLE_TOKEN = "J8WWuQDPmYSLfu/gXAG+UqbBy55KP2iE25QPNofzn040+NI9g7zeXLkIpXpC07SXvosrWsc1m8mxnq6hMiKwePbKJUwvSvqZb6s0sl1sfzh2mtRslV2Nc6tRKoxG/Qj+p3yGl1CC5ARbJJKGBaXcgq7Tnekn+ytw+RLlgoSAMOc="

# Replay Bytes für Phase 2 (Verschlüsselungshandshake Bypass)
# Extrahiert aus Log Source 39 und 40 
PHASE2_REPLAY_DATA = bytes.fromhex(
    "0c cb 9a 2b 5f 95 1e b6 69 df aa 37 5a 6b be 3e "
    "76 20 2e 13 c9 d1 aa 36 31 be 74 e5 05 d0 11 f8 "
    "52 fa 6a 88 c1 39 93 9a 6c 61 f9 fa 6a 88 c1 3b "
    "29 19 e1 22 35 f6 d0 41 2b 5f 95 1e b6 69 df aa "
    "37 19 e1 22 35 f6 2e 8d d5 db 72 8f 67 56 b8 5b "
    "31 be 74 e4"
)

# Base64 Payloads für Initialisierungs-Sequenz (Cmd 2-6)
CMD_2_PAYLOAD = base64.b64decode("y+DDbqMNNnV5LDju3xlEhSWl9peI5eWb2ghmr3wVyEI=")
CMD_10001_PAYLOAD = base64.b64decode("MzlB36X/IVo8ZzI5rG9j1w==")
CMD_3_PAYLOAD = base64.b64decode("I3mbwVIxJQgnSB9GJKNk5Cz4lHNuiNQuetIK1as++bY=")
CMD_4_PAYLOAD = CMD_2_PAYLOAD
CMD_5_PAYLOAD = base64.b64decode("36Rw4/b3Mw4tDnOS/p8mXQ8FnmDnjxA4yMQ9iXTIZQOw=")
CMD_6_PAYLOAD = base64.b64decode("90RH0Mg4PMffYI1fACycdPDFvKRV/22yeiZoDPKRFcyG0jH7mkZCE16ucxWcGAo3ZlwJ+GwTj5vj0L+gvGRmWg==")

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ArtemisFull")

# --- KONSTANTEN ---
class PacketType:
    LBCS_REQ = 0x41
    LBCS_RESP = 0x43
    DATA = 0xD0      # Artemis Commands / Login
    CONTROL = 0xD1   # ACKs / Pre-Header
    PRE_LOGIN = 0xF9

class InnerType:
    ACK_TYPE_00 = 0x00
    ACK_TYPE_01 = 0x01
    IMAGE_DATA = 0x04

# --- HELPER CLASSES (BLE & WIFI) ---

class NetworkManager:
    @staticmethod
    async def enable_camera_wifi(ble_mac):
        """Aktiviert das WLAN der Kamera über BLE."""
        logger.info(f"[BLE] Suche Kamera mit MAC {ble_mac}...")
        device = await BleakScanner.find_device_by_address(ble_mac, timeout=15.0)
        
        if not device:
            logger.warning("[BLE] Gerät nicht gefunden. Ist es bereits im WLAN-Modus?")
            return False

        try:
            logger.info(f"[BLE] Verbinde mit {ble_mac}...")
            async with BleakClient(device, timeout=20.0) as client:
                if not client.is_connected:
                    logger.error("[BLE] Verbindung fehlgeschlagen.")
                    return False
                
                logger.info("[BLE] Sende 'Magic Bytes' zum Aktivieren des WLANs...")
                await client.write_gatt_char(BLE_UUID_WRITE, BLE_WAKEUP_BYTES, response=True)
                logger.info("[BLE] Befehl gesendet. Kamera startet neu/aktiviert WLAN.")
                return True
        except Exception as e:
            logger.error(f"[BLE] Fehler: {e}")
            return False

    @staticmethod
    def connect_wifi_nmcli(ssid, password):
        """Verbindet den Host-Computer via nmcli mit dem Kamera-WLAN."""
        logger.info(f"[WIFI] Prüfe Verbindung zu '{ssid}'...")
        
        # 1. Prüfen ob bereits verbunden
        try:
            # iwgetid ist oft schneller, falls installiert
            res = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
            if ssid in res.stdout.strip():
                logger.info("[WIFI] Bereits verbunden.")
                return True
        except:
            pass

        # 2. Scannen (um sicherzugehen, dass das Netz da ist)
        logger.info("[WIFI] Scanne nach Netzwerken (das kann dauern)...")
        subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], capture_output=True)
        time.sleep(2) # Kurz warten nach Rescan

        # 3. Verbinden
        logger.info(f"[WIFI] Verbinde mit {ssid}...")
        cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", password]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode == 0:
            logger.info("[WIFI] Verbindung erfolgreich hergestellt!")
            # Warten bis DHCP IP vergeben hat
            time.sleep(3) 
            return True
        else:
            logger.error(f"[WIFI] Verbindung fehlgeschlagen: {proc.stderr.strip()}")
            return False

# --- PROTOKOLL LOGIK ---

class SequenceManager:
    def __init__(self):
        self.data_seq = 0       # Für D0 Pakete
        self.control_seq = 0    # Für D1 ACKs
        self.pending_acks = {}  # Wartende Pakete

    def next_data(self) -> int:
        seq = self.data_seq
        self.data_seq = (self.data_seq + 1) % 65536
        return seq

    def next_control(self) -> int:
        seq = self.control_seq
        self.control_seq = (self.control_seq + 1) % 65536
        return seq
    
    def set_data(self, seq):
        self.data_seq = seq

    def mark_pending(self, seq, packet):
        self.pending_acks[seq] = {"ts": time.time(), "pkt": packet, "retries": 0}

    def acknowledge(self, seq):
        if seq in self.pending_acks:
            del self.pending_acks[seq]
            return True
        return False

class PPPPSession:
    def __init__(self, ip, port, token):
        self.ip = ip
        self.port = port
        self.token = token
        self.sock = None
        self.seq_manager = SequenceManager()
        self.session_id = None
        self.is_connected = False

    def connect_socket(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.settimeout(2.0)
            # WICHTIG: Binden auf 0.0.0.0 hilft beim Empfang der Antworten
            self.sock.bind(('0.0.0.0', 0)) 
            logger.info("[NET] UDP Socket erstellt.")
        except Exception as e:
            logger.error(f"[NET] Socket Fehler: {e}")

    def close(self):
        if self.sock:
            self.sock.close()

    def _send_raw(self, data):
        if not self.sock: return
        try:
            self.sock.sendto(data, (self.ip, self.port))
        except Exception as e:
            logger.error(f"Send Fail: {e}")

    def _recv(self, timeout=None):
        if not self.sock: return None
        if timeout: self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(4096)
            
            # Basic Parsing für ACKs
            if len(data) > 4:
                magic, p_type, _ = struct.unpack('>BBH', data[:4])
                if magic == 0xF1 and p_type == PacketType.CONTROL:
                    # Parse ACKs (Inner Type 00/01)
                    inner = data[4:]
                    if len(inner) >= 4:
                        i_magic, i_type, _ = struct.unpack('>BBH', inner[:4])
                        if i_magic == 0xD1 and i_type in [0, 1]:
                            # Extrahiere Sequenznummern aus Payload
                            num_acks = (len(inner) - 4) // 2
                            for i in range(num_acks):
                                ack_seq = struct.unpack('>H', inner[4 + i*2 : 6 + i*2])[0]
                                if self.seq_manager.acknowledge(ack_seq):
                                    logger.debug(f"ACK erhalten für Seq {ack_seq}")

            return data
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Recv Error: {e}")
            return None

    # --- KRITISCHE OPTIMIERUNG: Pre-Command Header ---
    def send_pre_command_header(self, seq):
        """
        Sendet das D1-Paket, das einen kommenden D0-Befehl ankündigt.
        Dies entspricht exakt dem Muster im Log (Source 57 -> Source 58). 
        """
        # Payload besteht aus 10 Null-Bytes (Padding)
        payload = b'\x00' * 10
        
        # Inner Header: D1 00 [Seq]
        inner = struct.pack('>BBH', 0xD1, 0x00, seq)
        full_payload = inner + payload
        
        # Outer Header: F1 D1 [Len]
        outer = struct.pack('>BBH', 0xF1, PacketType.CONTROL, len(full_payload)) + full_payload
        
        logger.debug(f"TX Pre-Header (Seq={seq})")
        self._send_raw(outer)
        # Minimale Pause, damit die Kamera den Header verarbeiten kann
        time.sleep(0.01)

    def send_artemis_command(self, cmd_type, payload_bytes, seq=None):
        """Baut und sendet ein Artemis-Kommando inkl. Pre-Header."""
        
        # 1. Artemis Header & Payload Padding
        payload_len = len(payload_bytes)
        artemis_header = (
            b'ARTEMIS\x00' +
            struct.pack('<I', 2) +
            struct.pack('<I', cmd_type) +
            struct.pack('<I', payload_len) +
            payload_bytes
        )
        
        # 4-Byte Alignment Padding [cite: 4]
        if len(artemis_header) % 4 != 0:
            artemis_header += b'\x00' * (4 - (len(artemis_header) % 4))

        # 2. Sequenznummer
        if seq is None:
            seq = self.seq_manager.next_data()

        # 3. SENDE PRE-HEADER (Type D1)
        self.send_pre_command_header(seq)

        # 4. Sende DATA (Type D0)
        inner = struct.pack('>BBH', 0xD1, 0x00, seq)
        full_payload = inner + artemis_header
        outer = struct.pack('>BBH', 0xF1, PacketType.DATA, len(full_payload)) + full_payload

        logger.info(f"TX Command {cmd_type} (Seq={seq})")
        self._send_raw(outer)
        self.seq_manager.mark_pending(seq, outer)

    def wait_for_ack(self, seq, timeout=2.0):
        start = time.time()
        while time.time() - start < timeout:
            self._recv(timeout=0.1) # Checkt ACKs im Hintergrund
            if seq not in self.seq_manager.pending_acks:
                return True
        logger.warning(f"Timeout warten auf ACK Seq {seq}")
        return False

    # --- PHASEN ---

    def phase1_discovery(self):
        logger.info(">>> PHASE 1: LBCS Discovery")
        # Optimierung: Erst lauschen, falls Kamera schon broadcastet [cite: 1]
        logger.info("Lausche auf Broadcasts...")
        data = self._recv(timeout=2.0)
        if data and len(data) >= 28 and data[1] == 0x43:
             self.session_id = data[24:28]
             logger.info(f"✅ Passiv gefunden! Session ID: {self.session_id.hex()}")
             return True
        
        # Wenn nichts gehört, aktiv senden
        logger.info("Kein Broadcast, sende aktiven Discovery Request...")
        payload = b'LBCS' + b'\x00'*8 + b'CCCJJ' + b'\x00'*3
        packet = struct.pack('>BBH', 0xF1, PacketType.LBCS_REQ, len(payload)) + payload
        
        for _ in range(3):
            self._send_raw(packet)
            data = self._recv(timeout=1.0)
            if data and len(data) >= 28 and data[1] == PacketType.LBCS_RESP:
                self.session_id = data[24:28]
                logger.info(f"✅ Aktiv gefunden! Session ID: {self.session_id.hex()}")
                return True
        return False

    def phase2_encryption(self):
        logger.info(">>> PHASE 2: Pre-Login Encryption (Replay)")
        # Wir nutzen die Hardcoded Bytes aus dem Log [cite: 39]
        packet = struct.pack('>BBH', 0xF1, PacketType.PRE_LOGIN, len(PHASE2_REPLAY_DATA)) + PHASE2_REPLAY_DATA
        
        for i in range(3):
            self._send_raw(packet)
            time.sleep(0.1)
            # Auf ACK warten (Typ D0, Payload "ACK")
            resp = self._recv(timeout=1.0)
            if resp and b'ACK' in resp:
                logger.info("✅ Phase 2 Handshake bestätigt.")
                return True
        
        logger.warning("⚠️ Kein ACK für Phase 2 erhalten, versuche trotzdem weiter...")
        return True # Soft fail, oft klappt es trotzdem

    def phase3_login(self):
        logger.info(">>> PHASE 3: Login")
        # Token + Null + SessionID
        login_payload = self.token.encode('ascii') + b'\x00'
        if self.session_id:
            login_payload += self.session_id
        
        # Seq 0 für Login
        self.send_artemis_command(1, login_payload, seq=0)
        return self.wait_for_ack(0)

    def phase4_init(self):
        logger.info(">>> PHASE 4: Initialization")
        # Strikte Abfolge aus dem Log [cite: 78-200]
        
        # Cmd 2 (Seq 1)
        self.send_artemis_command(2, CMD_2_PAYLOAD, seq=1)
        self.wait_for_ack(1)

        # Cmd 10001 (Seq 2, 3) - Wird oft doppelt gesendet
        self.send_artemis_command(10001, CMD_10001_PAYLOAD, seq=2)
        self.wait_for_ack(2)
        self.send_artemis_command(10001, CMD_10001_PAYLOAD, seq=3)
        self.wait_for_ack(3)

        # Cmd 3 (Seq 5) - Achtung: Seq 4 wird oft übersprungen im Log
        self.seq_manager.set_data(5)
        self.send_artemis_command(3, CMD_3_PAYLOAD, seq=5)
        self.wait_for_ack(5)

        # Cmd 4 (Seq 6)
        self.send_artemis_command(4, CMD_4_PAYLOAD, seq=6)
        self.wait_for_ack(6)
        
        # Cmd 5 (Seq 7) - Config?
        self.send_artemis_command(5, CMD_5_PAYLOAD, seq=7)
        self.wait_for_ack(7)

        # Cmd 6 (Seq 8)
        self.send_artemis_command(6, CMD_6_PAYLOAD, seq=8)
        self.wait_for_ack(8)

        # Seq für Loop vorbereiten
        self.seq_manager.set_data(9)

    def run_session(self):
        self.connect_socket()
        
        if not self.phase1_discovery():
            logger.error("Discovery fehlgeschlagen.")
            return

        if not self.phase2_encryption():
            logger.error("Encryption Handshake fehlgeschlagen.")
            return

        if not self.phase3_login():
            logger.error("Login fehlgeschlagen.")
            return
        
        self.phase4_init()
        
        logger.info(">>> PHASE 5: Heartbeat Loop (Drücke Ctrl+C zum Beenden)")
        last_heartbeat = time.time()
        
        while True:
            try:
                # Schneller Heartbeat (alle 2s) [cite: 332]
                if time.time() - last_heartbeat > 2.0:
                    self.send_artemis_command(5, CMD_5_PAYLOAD)
                    last_heartbeat = time.time()
                
                # Empfange Daten (ACKs werden in _recv verarbeitet)
                self._recv(timeout=0.1)

            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Loop Error: {e}")
                break

# --- MAIN ---

async def main_async(args):
    # 1. BLE Wakeup
    if args.ble:
        success = await NetworkManager.enable_camera_wifi(DEFAULT_BLE_MAC)
        if success:
            logger.info("Warte 10 Sekunden auf WLAN-Boot der Kamera...")
            time.sleep(10)
        else:
            logger.warning("BLE Wakeup fehlgeschlagen (vielleicht schon an?)")

    # 2. WLAN Connect
    if args.wifi:
        success = NetworkManager.connect_wifi_nmcli(DEFAULT_WIFI_SSID, DEFAULT_WIFI_PASS)
        if not success:
            logger.error("Konnte WLAN nicht verbinden. Abbruch.")
            return

    # 3. Protokoll Start
    session = PPPPSession(DEFAULT_CAMERA_IP, DEFAULT_CAMERA_PORT, args.token)
    session.run_session()

def main():
    parser = argparse.ArgumentParser(description="Artemis Full Control")
    parser.add_argument("--wifi", action="store_true", default=True, help="Automatisch mit WLAN verbinden")
    parser.add_argument("--ble", action="store_true", default=True, help="Kamera per BLE aufwecken")
    parser.add_argument("--token", default=TEST_BLE_TOKEN, help="Login Token")
    args = parser.parse_args()

    # Prüfung auf Root für nmcli
    if os.geteuid() != 0:
        logger.warning("WARNUNG: Script läuft nicht als Root. WLAN-Verbindung (nmcli) könnte fehlschlagen!")

    asyncio.run(main_async(args))

if __name__ == "__main__":
    main()
