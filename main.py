import asyncio
import logging
import sys
import time

# Configure logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("Main")

from modules.ble_handler import BLEHandler
from modules.wifi_handler import WifiHandler
from modules.camera_client import CameraClient
import config

async def main():
    logger.info("Starting KJK230 Camera Controller...")

    # 0. Check Configuration
    if "AA:BB" in config.BLE_MAC_ADDRESS:
        logger.critical("Configuration invalid! Please update config.py with real values from Reverse Engineering.")
        return

    # Initialize Modules
    ble = BLEHandler()
    wifi = WifiHandler()
    cam = CameraClient()

    # 1. Wake up the Camera via BLE
    logger.info(">>> STEP 1: Waking up Camera via BLE...")
    if await ble.wake_camera():
        logger.info("Camera wakeup signal sent.")
    else:
        logger.error("Failed to wake camera. Aborting.")
        return

    # 2. Wait for WiFi and Connect
    logger.info(">>> STEP 2: Connecting to Camera WiFi...")
    # Give the camera a few seconds to boot its AP
    logger.info("Waiting 10s for Camera AP to initialize...")
    await asyncio.sleep(10)

    ssid = wifi.find_camera_ssid()
    if not ssid:
        logger.error("Camera WiFi SSID not found. Is the camera on?")
        return

    if not wifi.connect_to_camera(ssid):
        logger.error("Failed to establish WiFi connection. Aborting.")
        # Try to restore home wifi just in case we got stuck halfway
        wifi.restore_home_wifi()
        return

    # 3. Connect to TCP Server and Control
    logger.info(">>> STEP 3: Connecting to TCP Control Interface...")

    # Wait for network stability
    await asyncio.sleep(5)

    if cam.connect():
        # Perform Login
        if cam.login():
            # Get Device Info
            cam.get_device_info()

            # (Optional) Add more commands here (e.g. get file list if protocol known)

            logger.info("Interaction complete.")

        cam.close()
    else:
        logger.error("Failed to connect to Camera TCP Server.")

    # 4. Cleanup
    logger.info(">>> STEP 4: Cleanup & Disconnect...")
    wifi.restore_home_wifi()
    logger.info("Process Complete.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
