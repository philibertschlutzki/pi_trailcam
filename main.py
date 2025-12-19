import asyncio
import logging
import sys
import time
import struct
import socket
import subprocess
import json
import os
from bleak import BleakScanner, BleakClient

# --- CONFIG ---
# Deine IDs
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"
WIFI_SSID = "KJK_E0FF"
WIFI_PASS = "85087127"
WIFI_INTERFACE = "wlan0"

# Konstanten aus JADX & Wireshark
UUID_WRITE = "00000002-0000-1000-8000-00805f9b34fb" 
CMD_WAKEUP = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
CAMERA_IP = "192.168.43.1"
CAMERA_PORT = 40611 

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
        check = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
        if WIFI_SSID in check.stdout:
            logger.info("Bereits verbunden!")
        else:
            subprocess.run(["sudo", "nmcli", "connection", "delete", WIFI_SSID], capture_output=True)
            subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], capture_output=True)
            time.sleep(1)
            cmd = ["sudo", "nmcli", "device", "wifi", "connect", WIFI_SSID, "password", WIFI_PASS, "ifname", WIFI_INTERFACE]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                logger.error("WLAN Fehler!")
                return False
            logger.info("WLAN verbunden. Warte auf IP...")
            time.sleep(3)
        return True

class UDPWorker:
    @staticmethod
    def create_socket_bound_to_interface(interface_name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Zwingt Traffic über wlan0
        try:
            sock.setsockopt(socket.SOL_SOCKET, 25, interface_name.encode('utf-8'))
        except PermissionError:
            logger.error("FEHLER: Skript muss mit SUDO laufen!")
            return None
        sock.settimeout(2.0)
        return sock

    @staticmethod
    def create_packet(payload_bytes):
        # Header F1 D0 + 2 Bytes Länge
        header = struct.pack('>BBH', 0xF1, 0xD0, len(payload_bytes))
        return header + payload_bytes

    @staticmethod
    def run():
        logger.info(">>> SCHRITT 3: UDP Login (JSON Mode)")
        sock = UDPWorker.create_socket_bound_to_interface(WIFI_INTERFACE)
        if not sock: return
        target = (CAMERA_IP, CAMERA_PORT)

        # 1. Init (Port öffnen)
        sock.sendto(bytes.fromhex("f1e00000"), target)
        time.sleep(0.1)
        
        # 2. Login Varianten (Basierend auf JADX Findings: cmdId = 0)
        
        # Variante A: Standard JSON Login
        json_a = {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "supportHeartBeat": True
        }
        
        # Variante B: Minimal
        json_b = {
            "cmdId": 0,
            "usrName": "admin",
            "password": ""
        }

        # Variante C: Raw JSON (ohne Header) - Manche Apps machen das
        
        tests = [
            ("JSON mit Header (Standard)", UDPWorker.create_packet(json.dumps(json_a).encode('utf-8'))),
            ("JSON Minimal mit Header", UDPWorker.create_packet(json.dumps(json_b).encode('utf-8'))),
            ("JSON RAW (Ohne Header)", json.dumps(json_a).encode('utf-8')) 
        ]

        for name, packet in tests:
            logger.info(f"Teste: {name}...")
            for _ in range(2):
                sock.sendto(packet, target)
                try:
                    data, _ = sock.recvfrom(2048)
                    # Antwort ist meist F1 D0 ... oder JSON {"cmdId": 0, "result": 0}
                    if data.startswith(b'\xf1\xd0') or b'cmdId' in data:
                        logger.info(f"🎉 TREFFER! Login erfolgreich mit: {name}")
                        logger.info(f"Antwort: {data}")
                        
                        # Heartbeat Loop
                        while True:
                            time.sleep(2)
                            sock.sendto(bytes.fromhex("f1e00000"), target)
                            print(".", end="", flush=True)
                except socket.timeout:
                    pass
                time.sleep(0.5)

        logger.error("❌ Alle Login-Varianten fehlgeschlagen.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("BITTE MIT SUDO STARTEN!")
        sys.exit(1)
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        if loop.run_until_complete(NetworkHelper.enable_wifi_connection()):
            UDPWorker.run()
    except KeyboardInterrupt: pass
