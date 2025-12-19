import asyncio
import logging
import sys
import time
import struct
import socket
import subprocess
import json
from bleak import BleakScanner, BleakClient

# --- KONFIGURATION ---
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"
WIFI_SSID = "KJK_E0FF"
WIFI_PASS = "85087127"
WIFI_INTERFACE = "wlan0"

UUID_WRITE = "00000002-0000-1000-8000-00805f9b34fb" 
CMD_WAKEUP = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
ARTEMIS_TOKEN = "MzlB36X/IVo8ZzI5rG9j1w=="

CAMERA_IP = "192.168.43.1"
CAMERA_PORT = 40611 
LOCAL_PORT = 5085

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("KJK")

class BLEWorker:
    @staticmethod
    async def wake_camera_blindly():
        logger.info(f"PHASE 1: BLE Wakeup...")
        device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=8.0)
        if not device:
            logger.warning("Kamera BLE nicht gefunden. Weiter...")
            return True
        try:
            async with BleakClient(device) as client:
                logger.info("Sende Wake-Up...")
                try:
                    await client.write_gatt_char(UUID_WRITE, CMD_WAKEUP, response=True)
                except Exception: pass
        except Exception as e:
            logger.warning(f"BLE Fehler: {e}")
        return True

class WiFiWorker:
    @staticmethod
    def wait_and_connect(ssid, password, interface="wlan0"):
        logger.info(f"PHASE 2: WLAN Verbindung '{ssid}'...")
        # Profil Löschen für sauberen Start
        subprocess.run(["sudo", "nmcli", "connection", "delete", ssid], capture_output=True)
        
        for i in range(15):
            subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan", "ifname", interface], capture_output=True)
            time.sleep(1)
            check = subprocess.run(["nmcli", "-f", "SSID", "device", "wifi", "list", "ifname", interface], capture_output=True, text=True)
            
            if ssid in check.stdout:
                logger.info(f"WLAN gefunden! Verbinde...")
                cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", password, "ifname", interface]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode == 0:
                    logger.info("✅ WLAN verbunden!")
                    return True
            time.sleep(2)
        return False

class UDPWorker:
    @staticmethod
    def get_wlan_ip(interface="wlan0"):
        """Ermittelt die IP-Adresse des WLAN-Interfaces."""
        try:
            cmd = ["ip", "-4", "addr", "show", interface]
            result = subprocess.run(cmd, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "inet " in line:
                    # Format: inet 192.168.43.20/24 ...
                    return line.strip().split(" ")[1].split("/")[0]
        except Exception as e:
            logger.error(f"IP Ermittlung Fehler: {e}")
        return None

    @staticmethod
    def create_packet(payload_bytes):
        header = struct.pack('>BBH', 0xF1, 0xD0, len(payload_bytes))
        return header + payload_bytes

    @staticmethod
    def start_session():
        logger.info("PHASE 3: UDP Discovery & Login...")
        
        # 1. Lokale IP auf wlan0 ermitteln (WICHTIG!)
        local_ip = UDPWorker.get_wlan_ip(WIFI_INTERFACE)
        if not local_ip:
            logger.error(f"Konnte keine IP auf {WIFI_INTERFACE} finden!")
            return False, None, None
            
        logger.info(f"Binde Socket an Interface-IP: {local_ip}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        try:
            # Explizites Binden an die WLAN-IP verhindert Routing über eth0
            sock.bind((local_ip, LOCAL_PORT))
        except Exception as e:
            logger.error(f"Socket Bind Fehler: {e}")
            return False, None, None
        
        sock.settimeout(2.0)

        # --- A: DISCOVERY ---
        discovery_pkt = bytes.fromhex("f1300000")
        camera_addr = None
        
        logger.info("Sende Discovery (Broadcast & Unicast)...")
        for _ in range(5):
            # Broadcast ins Subnetz (x.x.x.255)
            subnet_broadcast = ".".join(local_ip.split(".")[:3]) + ".255"
            
            try:
                sock.sendto(discovery_pkt, (subnet_broadcast, 40611)) # Broadcast
                sock.sendto(discovery_pkt, (CAMERA_IP, 40611))        # Direkt
            except Exception as e:
                logger.warning(f"Send Fehler: {e}")

            try:
                while True:
                    data, addr = sock.recvfrom(1024)
                    logger.info(f"✅ Antwort von {addr} erhalten!")
                    camera_addr = addr
                    break
            except socket.timeout: pass
            
            if camera_addr: break
            time.sleep(1)
        
        if not camera_addr:
            logger.warning("Keine Antwort auf Discovery. Nutze Standard-IP.")
            camera_addr = (CAMERA_IP, 40611)

        # --- B: LOGIN ---
        # 1. Init
        sock.sendto(bytes.fromhex("f1e00000"), camera_addr)
        time.sleep(0.1)
        sock.sendto(bytes.fromhex("f1e10000"), camera_addr)
        time.sleep(0.5)

        # 2. Login (Artemis Token)
        logger.info("Sende Login Token...")
        token_bytes = ARTEMIS_TOKEN.encode('ascii') + b'\x00'
        p1 = b'\xd1\x00\x00\x05' + b'ARTEMIS\x00' + b'\x02\x00\x00\x00' + b'\x04\x00\x01\x00'
        p1 += struct.pack('<I', len(token_bytes)) + token_bytes
        
        packet = UDPWorker.create_packet(p1)
        
        for i in range(3):
            sock.sendto(packet, camera_addr)
            try:
                data, _ = sock.recvfrom(2048)
                if data.startswith(b'\xf1\xd0'):
                    logger.info("✅ LOGIN ERFOLGREICH!")
                    return True, sock, camera_addr
            except socket.timeout: pass
            time.sleep(1)

        # Fallback: JSON Login
        logger.info("Fallback: Versuche JSON Login...")
        login_json = {"cmdId":0, "usrName":"admin", "password":"admin", "supportHeartBeat":True}
        packet_json = UDPWorker.create_packet(json.dumps(login_json).encode('utf-8'))
        sock.sendto(packet_json, camera_addr)
        
        try:
            data, _ = sock.recvfrom(2048)
            if data.startswith(b'\xf1\xd0'):
                logger.info("✅ JSON LOGIN ERFOLGREICH!")
                return True, sock, camera_addr
        except socket.timeout: pass

        logger.error("❌ Login endgültig fehlgeschlagen.")
        return False, sock, camera_addr

# --- MAIN ---

async def main():
    logger.info("=== KJK Controller v4 (Fix Interface Binding) ===")
    
    await BLEWorker.wake_camera_blindly()
    
    if not WiFiWorker.wait_and_connect(WIFI_SSID, WIFI_PASS, WIFI_INTERFACE):
        return
        
    logger.info("Warte 5s auf DHCP...")
    await asyncio.sleep(5)
    
    success, sock, dest = UDPWorker.start_session()
    
    if success:
        logger.info("--- KAMERA VERBUNDEN ---")
        try:
            while True:
                await asyncio.sleep(3)
                logger.info("Ping...")
                sock.sendto(bytes.fromhex("f1e00000"), dest)
        except KeyboardInterrupt: pass
    
    if sock: sock.close()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
