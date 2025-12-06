import asyncio
import logging
import sys
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("Main")

from modules.ble_manager import BLEManager
from modules.wifi_manager import WiFiManager
from modules.camera_client import CameraClient
import config

async def heartbeat_loop(client, interval=2):
    """
    Periodically sends heartbeats to the camera.
    """
    logger.info("Starting Heartbeat Loop...")
    try:
        while True:
            client.send_heartbeat()
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("Heartbeat Loop Stopped.")

async def main():
    logger.info("Starting KJK230 Camera Controller...")

    # Step 1: Define MAC Address
    mac_address = config.BLE_MAC_ADDRESS
    if not mac_address:
        logger.info("BLE MAC Address not in config. Scanning...")
        mac_address = await BLEManager.scan_for_camera()
        if not mac_address:
            logger.critical("Could not find KJK Camera via BLE. Exiting.")
            return
        logger.info(f"Using found MAC Address: {mac_address}")
    else:
        logger.info(f"Using Configured MAC Address: {mac_address}")

    # Step 2: Wake up Camera
    logger.info(">>> STEP 2: Waking up Camera via BLE...")
    if not await BLEManager.wake_camera(mac_address):
        logger.error("Failed to wake camera. Exiting.")
        return

    # Step 3: Wait for WiFi
    logger.info(">>> STEP 3: Waiting for Camera WiFi (10s delay)...")
    await asyncio.sleep(10)

    wifi = WiFiManager()
    if not wifi.connect_to_camera_wifi():
         logger.error("Failed to connect to Camera WiFi. Exiting.")
         return

    # Step 4: Camera Client
    logger.info(">>> STEP 4: Initializing UDP Camera Client...")
    client = CameraClient()

    if client.connect():
        heartbeat_task = None
        try:
            # Step 5: Login
            logger.info(">>> STEP 5: Logging in...")
            if client.login():

                # Start Heartbeat Loop in background
                heartbeat_task = asyncio.create_task(heartbeat_loop(client))

                # Step 6: Get Device Info
                logger.info(">>> STEP 6: Getting Device Info...")
                info = client.get_device_info()
                logger.info(f"Device Info: {info}")

                # Step 7: Start Stream Session (Example)
                logger.info(">>> STEP 7: Starting Stream Session...")
                client.start_stream()

                # Keep session alive for a bit (simulate viewing)
                logger.info("Session active. Waiting 10 seconds...")
                await asyncio.sleep(10)

                # Stop Stream
                logger.info(">>> STEP 8: Stopping Stream...")
                client.stop_stream()

            else:
                logger.error("Login Failed.")
        except Exception as e:
            logger.error(f"Runtime error: {e}")
        finally:
            # Cancel heartbeat
            if heartbeat_task:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass

            # Close
            logger.info("Closing Connection...")
            client.close()
    else:
        logger.error("Failed to create UDP socket.")

    logger.info("Process Complete.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
