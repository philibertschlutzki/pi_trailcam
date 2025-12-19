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
WIFI_SSID = "KJK_E0FF"
WIFI_PASS = "85087127"
WIFI_INTERFACE = "wlan0"

# UUIDs für KJK/TC100
UUID_WRITE = "00000002-0000-1000-8000-00805f9b34fb" 

# 8-Byte Wake-Up (Standard)
CMD_WAKEUP = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# Token (Base64 String, null-terminiert)
ARTEMIS_TOKEN = "MzlB36X/IVo8ZzI5rG9j1w=="

# Standard IP (wird durch Discovery bestätigt)
CAMERA_IP = "192.168.43.1"
# Wir nutzen 0 als Platzhalter, wird durch Discovery gefunden
CAMERA_PORT = 40611 
LOCAL_PORT = 5085

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("KJK")

class BLEWorker:
    @staticmethod
    async def wake_camera_blindly():
        logger.info(f"PHASE 1: BLE Wakeup ({CAMERA_BLE_MAC})...")
        device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=8.0)
        if not device:
            logger.warning("Kamera BLE nicht gefunden (WLAN evtl. schon an?). Weiter...")
            return True
        
        try:
            async with BleakClient(device) as client:
                logger.info("Sende Wake-Up (Fire & Forget)...")
                try:
                    await client.write_gatt_char(UUID_WRITE, CMD_WAKEUP, response=True)
                except Exception:
                    pass # Ignoriere Fehler, Hauptsache gesendet
                logger.info("BLE Befehl gesendet.")
        except Exception as e:
            logger.warning(f"BLE Fehler: {e}")
        return True

class WiFiWorker:
    @staticmethod
    def wait_and_connect(ssid, password, interface="wlan0"):
        logger.info(f"PHASE 2: WLAN Verbindung '{ssid}'...")
        # Altes Profil löschen für sauberen Start
        subprocess.run(["sudo", "nmcli", "connection", "delete", ssid], capture_output=True)
        
        for i in range(20):
            # Scan erzwingen
            subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan", "ifname", interface], capture_output=True)
            time.sleep(1)
            
            # Prüfen
            check = subprocess.run(["nmcli", "-f", "SSID", "device", "wifi", "list", "ifname", interface], capture_output=True, text=True)
            
            if ssid in check.stdout:
                logger.info(f"WLAN gefunden! Verbinde...")
                cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", password, "ifname", interface]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode == 0:
                    logger.info("✅ WLAN verbunden!")
                    return True
            else:
                logger.info(f"Suche WLAN... ({i+1}/20)")
            time.sleep(2)
        return False

class UDPWorker:
    @staticmethod
    def start_session():
        logger.info("PHASE 3: UDP Discovery & Login...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Wichtig für Discovery!
        
        try:
            sock.bind(('0.0.0.0', LOCAL_PORT))
        except:
            pass
        
        sock.settimeout(2.0)

        # --- A: DISCOVERY (LAN Search) ---
        # Befehl: F1 30 00 00 (Wer ist da?)
        discovery_pkt = bytes.fromhex("f1300000")
        target_ports = [40611, 32108] # Standard Ports für Artemis
        
        camera_addr = None
        logger.info("Sende Discovery Broadcast...")
        
        found = False
        for _ in range(5):
            for port in target_ports:
                # Broadcast UND Unicast versuchen
                try:
                    sock.sendto(discovery_pkt, ('255.255.255.255', port))
                    sock.sendto(discovery_pkt, (CAMERA_IP, port))
                except: pass
            
            try:
                while True:
                    data, addr = sock.recvfrom(1024)
                    # Antwort ist meist F1 41...
                    logger.info(f"✅ Antwort von {addr} erhalten! (Len: {len(data)})")
                    camera_addr = addr
                    found = True
                    break
            except socket.timeout:
                pass
            
            if found: break
            logger.info("Suche Kamera... (Retry)")
        
        if not found:
            logger.error("❌ Kamera antwortet nicht auf Discovery (Firewall? IP?).")
            # Fallback: Wir versuchen es trotzdem mit der Standard-IP
            camera_addr = (CAMERA_IP, 40611)
            logger.warning(f"Versuche Fallback auf {camera_addr}...")

        # --- B: WAKEUP & LOGIN ---
        logger.info(f"Starte Login bei {camera_addr}...")
        
        # 1. Init
        sock.sendto(bytes.fromhex("f1e00000"), camera_addr)
        time.sleep(0.1)
        sock.sendto(bytes.fromhex("f1e10000"), camera_addr)
        time.sleep(0.5)
        
        # 2. Login Packet
        token_bytes = ARTEMIS_TOKEN.encode('ascii') + b'\x00'
        # Struktur: Cmd(5) + "ARTEMIS\0" + Ver(2) + Unk(1) + Len + Token
        payload = b'\xd1\x00\x00\x05' + b'ARTEMIS\x00' + b'\x02\x00\x00\x00' + b'\x04\x00\x01\x00'
        payload += struct.pack('<I', len(token_bytes)) + token_bytes                  
        
        header = struct.pack('>BBH', 0xF1, 0xD0, len(payload))
        login_packet = header + payload
        
        for i in range(3):
            logger.info(f"Sende Login Token ({i+1}/3)...")
            sock.sendto(login_packet, camera_addr)
            try:
                data, _ = sock.recvfrom(1024)
                # Erfolgreiche Antwort beginnt mit F1 D0
                if data.startswith(b'\xf1\xd0'):
                    logger.info("✅ UDP LOGIN ERFOLGREICH! Session offen.")
                    return True, sock, camera_addr
            except socket.timeout:
                pass
            time.sleep(1)
            
        logger.error("❌ Login fehlgeschlagen.")
        return False, sock, camera_addr

# --- MAIN ---

async def main():
    logger.info("=== KJK Controller ===")
    
    # 1. BLE
    await BLEWorker.wake_camera_blindly()
    
    # 2. WiFi
    if not WiFiWorker.wait_and_connect(WIFI_SSID, WIFI_PASS, WIFI_INTERFACE):
        return
        
    logger.info("Warte 5s auf Netzwerk-Stack...")
    await asyncio.sleep(5)
    
    # 3. UDP
    success, sock, dest = UDPWorker.start_session()
    
    if success:
        logger.info("--- SYSTEM BEREIT ---")
        try:
            while True:
                await asyncio.sleep(3)
                logger.info("Sende Heartbeat...")
                sock.sendto(bytes.fromhex("f1e00000"), dest)
                # sock.sendto(bytes.fromhex("f1e10000"), dest) # Sekundärer Heartbeat
        except KeyboardInterrupt:
            pass
    
    sock.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
