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
from modules.ble_token_listener import TokenListener
import config

async def main():
    """
    Complete workflow with 3 phases.
    Phase 1: BLE Wake
    Phase 2: Token Extraction via BLE
    Phase 3: UDP Login with variant testing
    """
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

    CAMERA_IP = config.CAM_IP
    ble_client = None

    try:
        # PHASE 1: BLE WAKE
        logger.info("="*60)
        logger.info("PHASE 1: BLE WAKE")
        logger.info("="*60)

        # Updated: Keep connection open for token extraction
        success, ble_client = await BLEManager.wake_camera(mac_address, keep_connected=True)

        if not success:
            logger.error("Failed to wake camera or establish BLE connection.")
            return

        if not ble_client or not ble_client.is_connected:
            logger.error("BLE Client not connected after wake phase.")
            return

        # Short sleep to allow camera to process wake (while keeping connection)
        await asyncio.sleep(2)

        # PHASE 2: TOKEN EXTRACTION
        logger.info("="*60)
        logger.info("PHASE 2: TOKEN EXTRACTION")
        logger.info("="*60)

        # Pass the existing client to the listener
        token_listener = TokenListener(mac_address, logger, client=ble_client)
        creds = await token_listener.listen(timeout=10)

        # We can disconnect BLE now
        logger.info("Token extracted. Disconnecting BLE...")
        await ble_client.disconnect()
        ble_client = None

        logger.info(f"✓ Token: {creds['token'][:20]}...")
        logger.info(f"✓ Sequence from BLE: {creds['sequence'].hex()}")

        # PHASE 3: UDP LOGIN
        logger.info("="*60)
        logger.info("PHASE 3: UDP LOGIN")
        logger.info("="*60)

        logger.info("Waiting for WiFi connection...")
        wifi = WiFiManager()
        if not wifi.connect_to_camera_wifi():
            logger.error("Failed to connect to Camera WiFi. Exiting.")
            return

        camera = CameraClient(CAMERA_IP, logger)
        camera.set_session_credentials(creds['token'], creds['sequence'])

        if camera.connect():
            # Attempt standard login first
            if camera.login():
                logger.info("\n" + "🎉 "*20)
                logger.info("AUTHENTICATION SUCCESSFUL!")
                logger.info("🎉 "*20 + "\n")
            # Fallback to variant testing if standard login fails
            elif camera.try_all_variants():
                logger.info("\n" + "🎉 "*20)
                logger.info("AUTHENTICATION SUCCESSFUL (via fallback)!")
                logger.info("🎉 "*20 + "\n")
            else:
                logger.error("✗ Login failed with all variants")
                camera.close()
                return False

            # Keep alive for demonstration
            logger.info("Keeping session alive for 10s...")
            await asyncio.sleep(10)
            camera.close()
            return True
        else:
            logger.error("Failed to connect UDP socket")
            return False

    except asyncio.TimeoutError:
        logger.error("✗ Token extraction timeout")
        return False
    except Exception as e:
        logger.error(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Ensure BLE client is disconnected if something failed
        if ble_client and ble_client.is_connected:
            logger.info("Cleaning up BLE connection...")
            try:
                await ble_client.disconnect()
            except Exception as e:
                logger.warning(f"Error disconnecting BLE: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
