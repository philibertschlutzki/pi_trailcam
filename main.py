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
from ble_token_listener import TokenListener
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

    try:
        # PHASE 1: BLE WAKE
        logger.info("="*60)
        logger.info("PHASE 1: BLE WAKE")
        logger.info("="*60)

        await BLEManager.wake_camera(mac_address)
        # Short sleep to allow camera to process wake
        await asyncio.sleep(2)

        # PHASE 2: TOKEN EXTRACTION
        logger.info("="*60)
        logger.info("PHASE 2: TOKEN EXTRACTION")
        logger.info("="*60)

        token_listener = TokenListener(mac_address, logger)
        creds = await token_listener.listen(timeout=10)

        logger.info(f"✓ Token: {creds['token'][:20]}...")
        logger.info(f"✓ Sequence from BLE: {creds['sequence'].hex()}")

        # PHASE 3: UDP LOGIN WITH VARIANT TESTING
        logger.info("="*60)
        logger.info("PHASE 3: UDP LOGIN WITH VARIANT TESTING")
        logger.info("="*60)

        logger.info("Waiting for WiFi connection...")
        wifi = WiFiManager()
        if not wifi.connect_to_camera_wifi():
            logger.error("Failed to connect to Camera WiFi. Exiting.")
            return

        camera = CameraClient(CAMERA_IP, logger)
        camera.set_session_credentials(creds['token'], creds['sequence'])

        if camera.connect():
            # Try all variants starting with MYSTERY_09_01 (from tcpdump)
            if camera.login_all_variants():
                logger.info("\n" + "🎉 "*20)
                logger.info("AUTHENTICATION SUCCESSFUL!")
                logger.info("🎉 "*20 + "\n")

                # Keep alive for demonstration
                logger.info("Keeping session alive for 10s...")
                await asyncio.sleep(10)
                camera.close()
                return True
            else:
                logger.error("✗ Login failed with all variants")
                camera.close()
                return False
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

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
