import asyncio
import logging
import sys
import time
import struct
import socket
import json
import subprocess
from bleak import BleakScanner, BleakClient

# --- CONFIGURATION ---
# Replace with your camera's actual MAC address if known to speed up connection
CAMERA_BLE_MAC = "C6:1E:0D:E0:32:E8"  # Auto-scan if None

# UUIDs for KJK Camera (Standard for this chipset)
# These are the standard Artemis BLE Service/Char UUIDs
UUID_SERVICE = "0000ffe0-0000-1000-8000-00805f9b34fb"
UUID_WRITE   = "0000ffe1-0000-1000-8000-00805f9b34fb"
UUID_NOTIFY  = "0000ffe2-0000-1000-8000-00805f9b34fb"

# The "Magic" Wake-up Command [0x13, 0x57, 0x01...] found in DevSetupDialog.java
CMD_WAKEUP = bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])

# The Static UDP Token (Derived from Wireshark Frame 2743)
ARTEMIS_TOKEN = "MzlB36X/IVo8ZzI5rG9j1w=="

# UDP Settings
CAMERA_IP = "192.168.43.1" # Standard IP for the camera AP
CAMERA_PORT = 40611        # Port found in logs
LOCAL_PORT = 5085          # Local port to bind to

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("KJK_Controller")

# --- GLOBAL STATE ---
wifi_creds = {"ssid": None, "pwd": None}
stop_event = asyncio.Event()

# --- MODULES ---

class BLEWorker:
    @staticmethod
    async def wake_and_get_creds():
        """Connects via BLE, sends wake command, waits for WiFi creds."""
        logger.info(f"Scanning for camera ({CAMERA_BLE_MAC if CAMERA_BLE_MAC else 'Auto'})...")

        device = None
        if CAMERA_BLE_MAC:
            device = await BleakScanner.find_device_by_address(CAMERA_BLE_MAC, timeout=10.0)
        else:
            device = await BleakScanner.find_device_by_filter(
                lambda d, ad: d.name and ("KJK" in d.name or "Trail" in d.name),
                timeout=10.0
            )

        if not device:
            logger.error("Camera not found via BLE.")
            return False

        logger.info(f"Found device: {device.name} ({device.address})")

        def notification_handler(sender, data):
            # Parse incoming data. The App skips the first 8 bytes (header) then parses string.
            try:
                # Payload format: [Header 8B] [JSON String]
                if len(data) > 8:
                    payload = data[8:]
                    text_data = payload.decode('utf-8', errors='ignore')

                    # Look for JSON start
                    if "{" in text_data:
                        json_str = text_data[text_data.find("{"):]
                        logger.debug(f"Received BLE Data: {json_str}")

                        try:
                            data = json.loads(json_str)
                            if "ssid" in data and "pwd" in data:
                                wifi_creds["ssid"] = data["ssid"]
                                wifi_creds["pwd"] = data["pwd"]
                                logger.info(f"CAPTURED CREDENTIALS -> SSID: {wifi_creds['ssid']}, PASS: {wifi_creds['pwd']}")
                                stop_event.set() # Signal that we have what we need
                        except json.JSONDecodeError:
                            pass # Might be a partial packet, ignore
            except Exception as e:
                logger.error(f"Error parsing BLE notification: {e}")

        async with BleakClient(device) as client:
            logger.info("BLE Connected!")

            await client.start_notify(UUID_NOTIFY, notification_handler)
            logger.info("Subscribed to notifications.")

            logger.info("Sending Wake-Up Command...")
            await client.write_gatt_char(UUID_WRITE, CMD_WAKEUP)

            # Wait for credentials (timeout 20s as camera boots WiFi)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=20.0)
            except asyncio.TimeoutError:
                logger.warning("Timed out waiting for WiFi credentials via BLE.")

            logger.info("Disconnecting BLE...")

        return wifi_creds["ssid"] is not None

class WiFiWorker:
    @staticmethod
    def connect(ssid, password):
        """Connects to WiFi using nmcli (Linux NetworkManager)."""
        logger.info(f"Attempting WiFi connection to {ssid}...")

        # 1. Rescan to ensure AP is visible
        subprocess.run(["nmcli", "device", "wifi", "rescan"], capture_output=True)
        time.sleep(3) # Give scan a moment

        # 2. Connect
        # WARNING: This will disconnect your current WiFi. Ensure you have another way to control the Pi!
        cmd = ["nmcli", "device", "wifi", "connect", ssid, "password", password]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode == 0:
            logger.info("WiFi Connected Successfully!")
            return True
        else:
            logger.error(f"WiFi Connection Failed: {proc.stderr}")
            return False

class UDPWorker:
    @staticmethod
    def start_session():
        """Performs the UDP Handshake and Login using the correct Artemis Token."""
        logger.info("Starting UDP Session...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind(('0.0.0.0', LOCAL_PORT))
        except Exception as e:
            logger.warning(f"Could not bind to fixed port {LOCAL_PORT}, letting OS choose: {e}")

        sock.settimeout(5.0)
        dest = (CAMERA_IP, CAMERA_PORT)

        # 1. Send UDP Wakeup Packets (Standard Artemis/Goke protocol)
        logger.info("Sending UDP Init packets...")
        sock.sendto(bytes.fromhex("f1e00000"), dest)
        time.sleep(0.1)
        sock.sendto(bytes.fromhex("f1e10000"), dest)
        time.sleep(0.5)

        # 2. Build Login Packet using the STATIC TOKEN (Correction from previous attempts)
        # Payload Structure: [CmdID 4B] [Protocol 8B] [Ver 4B] [Unk 4B] [TokenLen 4B] [Token Var]

        token_bytes = ARTEMIS_TOKEN.encode('ascii') + b'\x00' # Null terminate the token

        payload = b''
        payload += b'\xd1\x00\x00\x05'          # Command ID (Handshake/Login)
        payload += b'ARTEMIS\x00'               # Protocol Signature
        payload += b'\x02\x00\x00\x00'          # Version 2
        payload += b'\x04\x00\x01\x00'          # Unknown constant
        payload += struct.pack('<I', len(token_bytes)) # Token Length (Little Endian)
        payload += token_bytes                  # The Token Itself

        # Header Construction: Magic(F1) + Type(D0) + PayloadLength(Big Endian)
        header = struct.pack('>BBH', 0xF1, 0xD0, len(payload))

        login_packet = header + payload

        logger.info(f"Sending Login Packet ({len(login_packet)} bytes)...")
        # logger.debug(f"Packet Hex: {login_packet.hex()}")

        sock.sendto(login_packet, dest)

        # 3. Wait for Response
        try:
            data, addr = sock.recvfrom(1024)
            logger.info(f"Received UDP Response from {addr}: {data.hex()}")

            # Valid response starts with Magic F1 and Type D0
            if data.startswith(b'\xf1\xd0'):
                logger.info("SUCCESS: Camera accepted login! UDP Channel Open.")
                return True, sock
            else:
                logger.warning(f"Received unexpected response type: {data.hex()[:4]}")
                return False, sock
        except socket.timeout:
            logger.error("UDP Login Timed Out. (Check IP/Firewall)")
            return False, sock

# --- MAIN WORKFLOW ---

async def main():
    logger.info("=== KJK Camera Automation Script ===")

    # PHASE 1: BLE Wakeup & Credential Fetch
    if not await BLEWorker.wake_and_get_creds():
        logger.error("Aborting: Failed to get WiFi credentials via BLE.")
        return

    # PHASE 2: WiFi Connection
    # Note: Ensure this doesn't lock you out of SSH!
    if not WiFiWorker.connect(wifi_creds["ssid"], wifi_creds["pwd"]):
        logger.error("Aborting: Failed to connect to Camera WiFi.")
        return

    # Wait for DHCP and UDP stack initialization on the camera
    logger.info("Waiting 5 seconds for network stack to settle...")
    await asyncio.sleep(5)

    # PHASE 3: UDP Login
    success, sock = UDPWorker.start_session()

    if success:
        logger.info("Workflow Complete. Entering Heartbeat Loop...")
        try:
            while True:
                await asyncio.sleep(3)
                logger.info("Sending Heartbeat (Keep-Alive)...")
                # Send Heartbeat (Packet Type E0)
                sock.sendto(bytes.fromhex("f1e00000"), (CAMERA_IP, CAMERA_PORT))
        except KeyboardInterrupt:
            logger.info("Stopping...")

    sock.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
