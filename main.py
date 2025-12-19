import asyncio
import logging
import sys
import time
import socket
import subprocess
import json
import os
from bleak import BleakScanner, BleakClient

# --- CONFIG ---
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"
WIFI_SSID = "KJK_E0FF"
WIFI_PASS = "85087127"
WIFI_INTERFACE = "wlan0"

# Ziel aus dem Log
CAMERA_IP = "192.168.43.1"
CAMERA_PORT = 40611 
# Quelle aus dem Log ("Start connect by lan, port:5085")
LOCAL_PORT = 5085

# UUIDs
UUID_WRITE = "00000002-0000-1000-8000-00805f9b34fb" 
CMD_WAKEUP = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("KJK")

class NetworkHelper:
    @staticmethod
    async def enable_wifi_connection():
        # 1. BLE Wakeup
        logger.info(">>> SCHRITT 1: BLE Wakeup")
        dev = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=5)
        if dev:
            async with BleakClient(dev) as client:
                try: await client.write_gatt_char(UUID_WRITE, CMD_WAKEUP, response=True)
                except: pass
                logger.info("Wakeup gesendet.")
        
        # 2. WLAN Connect
        logger.info(f">>> SCHRITT 2: Verbinde WLAN {WIFI_SSID}...")
        
        # Wir löschen das Profil vorher NICHT, wenn es schon da ist, um Zeit zu sparen
        # aber wir stellen sicher, dass wir verbunden sind.
        subprocess.run(["sudo", "nmcli", "device", "wifi", "connect", WIFI_SSID, "password", WIFI_PASS, "ifname", WIFI_INTERFACE], capture_output=True)
        
        # Check IP
        for i in range(10):
            ip = NetworkHelper.get_wlan_ip()
            if ip:
                logger.info(f"WLAN verbunden! Eigene IP: {ip}")
                return ip
            time.sleep(1)
            
        logger.error("Keine IP Adresse bekommen!")
        return None

    @staticmethod
    def get_wlan_ip():
        try:
            cmd = ["ip", "-4", "addr", "show", WIFI_INTERFACE]
            result = subprocess.run(cmd, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "inet " in line:
                    return line.strip().split(" ")[1].split("/")[0]
        except: pass
        return None

class AppLogic:
    @staticmethod
    def run(local_ip):
        logger.info(">>> SCHRITT 3: Login (Exakt wie im Log)")
        
        # Socket erstellen
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # WICHTIG: Bindung an Interface UND Port 5085 (wie im Log)
        try:
            sock.setsockopt(socket.SOL_SOCKET, 25, WIFI_INTERFACE.encode('utf-8'))
            logger.info(f"Socket an {WIFI_INTERFACE} gebunden.")
            
            # Binden an die lokale IP und Port 5085
            sock.bind((local_ip, LOCAL_PORT))
            logger.info(f"Socket an {local_ip}:{LOCAL_PORT} gebunden.")
        except Exception as e:
            logger.error(f"Binding Fehler: {e}")
            return

        sock.settimeout(3.0)
        target = (CAMERA_IP, CAMERA_PORT)

        # Das exakte JSON aus dem Log
        # "utcTime" passen wir dynamisch an
        login_payload = {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "needAudio": 0,
            "utcTime": int(time.time()),
            "supportHeartBeat": True
        }
        
        json_bytes = json.dumps(login_payload).encode('utf-8')
        
        logger.info(f"Sende JSON an {target}...")
        # Versuch 1: Nur JSON (wie im Log impliziert)
        sock.sendto(json_bytes, target)
        
        # Versuch 2: JSON mit Header (Falls der Log den Header verschweigt)
        # Header: F1 D0 + 2 Byte Länge
        header = struct.pack('>BBH', 0xF1, 0xD0, len(json_bytes))
        packet_with_header = header + json_bytes
        
        # Wir warten auf Antwort
        for i in range(5):
            try:
                data, addr = sock.recvfrom(2048)
                logger.info(f"✅ ANTWORT ERHALTEN von {addr}!")
                logger.info(f"Daten: {data}")
                
                # Wenn wir hier sind, sind wir drin!
                # Token holen (nächster Schritt im Log: cmdId 512)
                AppLogic.do_token_request(sock, target)
                return
            except socket.timeout:
                logger.info(f"Keine Antwort... (Versuch {i+1})")
                # Beim Retry senden wir abwechselnd mit/ohne Header, um sicherzugehen
                if i % 2 == 0:
                    logger.info("Sende mit Header...")
                    sock.sendto(packet_with_header, target)
                else:
                    logger.info("Sende RAW JSON...")
                    sock.sendto(json_bytes, target)
    
    @staticmethod
    def do_token_request(sock, target):
        logger.info("Hole Geräte-Infos (Token)...")
        # Im Log: {"cmdId":512} -> Antwort enthält Token
        req = json.dumps({"cmdId": 512}).encode('utf-8')
        sock.sendto(req, target)
        try:
            data, _ = sock.recvfrom(4096)
            logger.info(f"✅ INFO ERHALTEN: {data}")
        except:
            logger.warning("Keine Info-Antwort.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("BITTE MIT SUDO STARTEN!")
        sys.exit(1)
        
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        local_ip = loop.run_until_complete(NetworkHelper.enable_wifi_connection())
        
        if local_ip:
            AppLogic.run(local_ip)
            
    except KeyboardInterrupt: pass
