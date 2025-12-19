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

# WLAN Zugangsdaten (Aus deinem Log)
WIFI_SSID = "KJK_E0FF"
WIFI_PASS = "85087127"

# UUIDs für KJK/TC100 Kamera
UUID_WRITE   = "00000002-0000-1000-8000-00805f9b34fb" 

# Der 8-Byte Wake-Up Befehl (Java App Standard)
CMD_WAKEUP = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# Der Statische UDP Token (Aus Wireshark)
ARTEMIS_TOKEN = "MzlB36X/IVo8ZzI5rG9j1w=="

# UDP Settings
CAMERA_IP = "192.168.43.1"
CAMERA_PORT = 40611        
LOCAL_PORT = 5085          

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("KJK_Controller")

# --- MODULES ---

class BLEWorker:
    @staticmethod
    async def wake_camera():
        """Connects via BLE and sends wake command blindly."""
        logger.info(f"Scanning for camera ({CAMERA_BLE_MAC})...")
        
        device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=10.0)

        if not device:
            logger.error("Camera not found via BLE.")
            return False

        logger.info(f"Found device: {device.name}")

        async with BleakClient(device) as client:
            logger.info("BLE Connected!")
            
            # Wir warten nicht mehr auf Notifications, wir feuern nur den Befehl ab.
            logger.info("Sending Wake-Up Command...")
            try:
                await client.write_gatt_char(UUID_WRITE, CMD_WAKEUP, response=True)
                logger.info("Command sent successfully.")
            except Exception as e:
                logger.warning(f"Write failed (might still have worked): {e}")
            
            logger.info("Waiting 3 seconds to ensure command is processed...")
            await asyncio.sleep(3)
            logger.info("Disconnecting BLE...")

        return True

class WiFiWorker:
    @staticmethod
    def connect(ssid, password):
        """Connects to WiFi using nmcli."""
        logger.info(f"Attempting WiFi connection to {ssid}...")
        
        # 1. Rescan
        subprocess.run(["nmcli", "device", "wifi", "rescan"], capture_output=True)
        time.sleep(2) 
        
        # 2. Connect
        logger.info(f"Connecting to {ssid} with password {password}...")
        cmd = ["nmcli", "device", "wifi", "connect", ssid, "password", password]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        
        if proc.returncode == 0:
            logger.info("WiFi Connected Successfully!")
            return True
        else:
            logger.error(f"WiFi Connection Failed: {proc.stderr}")
            # Manchmal klappt es beim zweiten Versuch besser
            return False

class UDPWorker:
    @staticmethod
    def start_session():
        """Performs the UDP Handshake and Login."""
        logger.info("Starting UDP Session...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('0.0.0.0', LOCAL_PORT))
        except Exception:
            logger.warning(f"Port {LOCAL_PORT} busy, using random port.")
        
        sock.settimeout(5.0)
        dest = (CAMERA_IP, CAMERA_PORT)

        # 1. UDP Init / Ping
        logger.info("Sending UDP Init packets...")
        sock.sendto(bytes.fromhex("f1e00000"), dest)
        time.sleep(0.1)
        sock.sendto(bytes.fromhex("f1e10000"), dest)
        time.sleep(0.5)

        # 2. Login Packet
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
        
        logger.info(f"Sending Login Packet ({len(login_packet)} bytes)...")
        sock.sendto(login_packet, dest)

        # 3. Wait for Response
        try:
            data, addr = sock.recvfrom(1024)
            logger.info(f"Received UDP Response: {data.hex()}")
            if data.startswith(b'\xf1\xd0'):
                return True, sock
            return False, sock
        except socket.timeout:
            logger.error("UDP Login Timed Out.")
            return False, sock

# --- MAIN WORKFLOW ---

async def main():
    logger.info("=== KJK Camera Automation (Hardcoded Creds) ===")

    # PHASE 1: BLE Wakeup
    if not await BLEWorker.wake_camera():
        return

    # PHASE 2: WiFi Connection
    # Wir geben der Kamera Zeit, das WLAN hochzufahren
    logger.info("Waiting 10 seconds for Camera WiFi to become ready...")
    await asyncio.sleep(10)
    
    if not WiFiWorker.connect(WIFI_SSID, WIFI_PASS):
        logger.error("Aborting: Could not connect to WiFi.")
        return

    # Wait for DHCP
    logger.info("Waiting 5 seconds for IP address...")
    await asyncio.sleep(5)

    # PHASE 3: UDP Login
    success, sock = UDPWorker.start_session()
    
    if success:
        logger.info("SUCCESS! Connected to Camera via UDP.")
        logger.info("Entering Heartbeat Loop (Press Ctrl+C to stop)...")
        try:
            while True:
                await asyncio.sleep(3)
                # Heartbeat senden
                sock.sendto(bytes.fromhex("f1e00000"), (CAMERA_IP, CAMERA_PORT))
        except KeyboardInterrupt:
            pass
    
    sock.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
