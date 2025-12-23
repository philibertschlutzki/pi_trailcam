import socket
import struct
import time
import json
import logging
import sys
import argparse
import subprocess
import asyncio
import os
import netifaces
from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# --- CONFIGURATION ---
DEFAULT_CAMERA_IP = "192.168.43.1"
DEFAULT_CAMERA_PORT = 40611
DEFAULT_WIFI_SSID = "KJK_E0FF"
DEFAULT_WIFI_PASS = "85087127"
DEFAULT_BLE_MAC = "C6:1E:0D:E0:32:E8"

# BLE Constants
BLE_UUID_WRITE = "00000002-0000-1000-8000-00805f9b34fb"
BLE_WAKEUP_BYTES = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# EXACT LBCS HANDSHAKE PAYLOAD
# Magic: F1 41, Length: 20 Bytes (0x14)
LBCS_HANDSHAKE_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")

# Crypto
PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ArtemisClient")

# --- PROTOCOL TYPES ---
class PacketType:
    LBCS_REQ = 0x41
    LBCS_RESP = 0x43  
    DATA = 0xD0
    CONTROL = 0xD1
    PRE_LOGIN = 0xF9

class BLEWorker:
    @staticmethod
    async def wake_camera(mac_address):
        logger.info(f"Scanning for BLE device {mac_address}...")
        try:
            device = await BleakScanner.find_device_by_address(mac_address, timeout=45.0)
            if not device:
                logger.warning("❌ BLE Device not found.")
                return False

            logger.info(f"Device found! Connecting...")
            async with BleakClient(device, timeout=15.0) as client:
                logger.info("BLE Connected. Sending Wakeup Magic Bytes...")
                await client.write_gatt_char(BLE_UUID_WRITE, BLE_WAKEUP_BYTES, response=True)
                logger.info("✅ BLE Wakeup Sent.")
                return True
        except Exception as e:
            logger.error(f"BLE Error: {e}")
            return False

class WiFiWorker:
    @staticmethod
    def connect_nmcli(ssid, password):
        logger.info(f"Connecting to Wi-Fi {ssid} via nmcli...")
        try:
            res = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
            if ssid in res.stdout.strip():
                logger.info("Already connected to correct Wi-Fi.")
                return True
        except FileNotFoundError: pass 

        subprocess.run(["sudo", "nmcli", "connection", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], capture_output=True)
        time.sleep(3)
        cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", password]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode == 0:
            logger.info("Wi-Fi Connected.")
            return True
        else:
            logger.error(f"Wi-Fi Connection Failed: {proc.stderr.strip()}")
            return False

class PPPPSession:
    def __init__(self, target_ip, target_port):
        self.target_ip = target_ip
        self.target_port = target_port
        self.sock = None
        self.session_id = None
        self.local_ip = None

    def get_correct_interface_ip(self):
        """Finds the interface IP connected to the 192.168.43.x network"""
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for link in addrs[netifaces.AF_INET]:
                    ip = link['addr']
                    if ip.startswith("192.168.43."): # Camera Subnet
                        return ip
        return None

    def connect(self):
        # 1. Find correct Interface IP
        self.local_ip = self.get_correct_interface_ip()
        
        if not self.local_ip:
            logger.error("❌ Could not find local IP in 192.168.43.x range! Are you connected to Wi-Fi?")
            # Fallback: Try to connect to target to let OS decide route, then get sockname
            try:
                temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                temp_sock.connect((self.target_ip, 80))
                self.local_ip = temp_sock.getsockname()[0]
                temp_sock.close()
            except:
                raise ConnectionError("No network route to camera")

        logger.info(f"Binding to Local Interface IP: {self.local_ip}")

        # 2. Bind Socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.settimeout(2.0)
        
        # Explicitly bind to the Wi-Fi interface IP
        self.sock.bind((self.local_ip, 0))
        logger.info(f"UDP Socket bound to {self.local_ip}:{self.sock.getsockname()[1]}")

    def close(self):
        if self.sock: self.sock.close()

    def _send(self, data, dest_ip=None):
        if not self.sock: return
        target = dest_ip if dest_ip else self.target_ip
        try:
            self.sock.sendto(data, (target, self.target_port))
        except Exception as e:
            logger.error(f"Send Error: {e}")

    def _recv(self, timeout=None):
        if not self.sock: return None, None
        if timeout: self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(4096)
            return data, addr
        except socket.timeout:
            return None, None
        except Exception as e:
            logger.error(f"Recv Error: {e}")
            return None, None

    # --- PHASE 1: LBCS DISCOVERY (BROADCAST) ---
    def phase1_handshake(self):
        packet = LBCS_HANDSHAKE_PAYLOAD
        
        # Calculate Subnet Broadcast (e.g., 192.168.43.255)
        # Assuming /24 subnet which is standard for these cameras
        subnet_broadcast = self.local_ip.rsplit('.', 1)[0] + ".255"

        logger.info(f"Sending LBCS Discovery to {subnet_broadcast} and {self.target_ip}...")
        
        for i in range(10): # Try 10 times
            # 1. Send to Subnet Broadcast (Specific to Wi-Fi Interface)
            self._send(packet, dest_ip=subnet_broadcast)
            # 2. Send to Global Broadcast (Fallback)
            self._send(packet, dest_ip="255.255.255.255")
            # 3. Send Unicast
            self._send(packet, dest_ip=self.target_ip)
            
            # Wait for response
            data, addr = self._recv(timeout=1.0)
            
            if data and len(data) >= 4:
                magic, ptype, _ = struct.unpack('>BBH', data[:4])
                
                # Check for LBCS Response (0xF1 0x43)
                if magic == 0xF1 and ptype == PacketType.LBCS_RESP:
                    logger.info(f"✅ LBCS Handshake Success! Reply from {addr[0]}")
                    
                    if len(data) >= 28:
                        self.session_id = data[24:28]
                        logger.info(f"🔑 Session ID: {self.session_id.hex()}")
                    return True
            
            logger.info(f"Attempt {i+1}: No valid response, retrying...")
            
        return False

    # --- PHASE 2: LOGIN / CRYPTO ---
    def phase2_pre_login(self):
        payload_dict = {
            "utcTime": int(time.time()),
            "nonce": os.urandom(8).hex()
        }
        json_str = json.dumps(payload_dict, separators=(',', ':'))
        
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))
        
        full_content = PHASE2_STATIC_HEADER + encrypted
        header = struct.pack('>BBH', 0xF1, PacketType.PRE_LOGIN, len(full_content))
        packet = header + full_content
        
        logger.info("Sending Pre-Login (Crypto Init)...")
        for i in range(3):
            self._send(packet)
            data, _ = self._recv(timeout=1.0)
            if data:
                logger.info("✅ Pre-Login Response Received.")
                return True
        return True 

    def heartbeat_loop(self):
        logger.info(">>> Starting Heartbeat Loop (Every 3s)...")
        last_beat = 0
        while True:
            if time.time() - last_beat > 3.0:
                self._send(LBCS_HANDSHAKE_PAYLOAD)
                last_beat = time.time()
                
            data, _ = self._recv(timeout=0.1)
            if data and len(data) > 0:
                # logger.info(f"RX: {data.hex()[:20]}...")
                pass

    def run(self):
        try:
            self.connect()
            if self.phase1_handshake():
                self.phase2_pre_login()
                self.heartbeat_loop()
            else:
                logger.error("❌ Handshake failed on Port 40611.")
        except Exception as e:
             logger.error(f"Critical Error: {e}")
        finally:
            self.close()

# --- MAIN ---

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wifi", action="store_true", help="Connect Wi-Fi")
    parser.add_argument("--ble", action="store_true", help="Send BLE Wakeup")
    args = parser.parse_args()

    # 1. BLE
    if args.ble:
        if asyncio.run(BLEWorker.wake_camera(DEFAULT_BLE_MAC)):
            logger.info("Waiting 15s for Camera Wi-Fi to start...")
            time.sleep(15)

    # 2. Wi-Fi
    if args.wifi:
        if not WiFiWorker.connect_nmcli(DEFAULT_WIFI_SSID, DEFAULT_WIFI_PASS):
            return

    # 3. UDP Session (Port 40611)
    logger.info(f"[*] Starting Session to {DEFAULT_CAMERA_IP}:{DEFAULT_CAMERA_PORT}...")
    session = PPPPSession(DEFAULT_CAMERA_IP, DEFAULT_CAMERA_PORT)
    session.run()

if __name__ == "__main__":
    main()
