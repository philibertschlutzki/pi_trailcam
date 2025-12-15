import asyncio
import logging
import sys
import time

# Configure logging
import argparse

parser = argparse.ArgumentParser(description="KJK230 Camera Controller")
parser.add_argument("--debug", action="store_true", help="Enable debug logging")
args, unknown = parser.parse_known_args()

logging.basicConfig(
    level=logging.DEBUG if args.debug else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("Main")

if args.debug:
    logger.info("Debug mode enabled")

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
    
    FIX #25: Added proper timing between BLE wakeup and UDP connection.
    Camera's UDP stack needs ~8 seconds to initialize after BLE magic packet.
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

        # PHASE 2: TOKEN EXTRACTION
        logger.info("="*60)
        logger.info("PHASE 2: TOKEN EXTRACTION")
        logger.info("="*60)

        # FIX #18: Register notification handler IMMEDIATELY
        # (before camera sends data, which happens ~1-5 seconds after magic packet)
        # This prevents race condition where camera sends token before handler is ready
        token_listener = TokenListener(mac_address, logger, client=ble_client)
        
        logger.info("Registering notification handler...")
        await token_listener.start_listening()
        logger.info("Notification handler is ready to receive token.")

        # Now wait for camera to send token notification
        # (camera sends token ~1-5 seconds after magic packet)
        # Timeout increased to 15s because camera needs time to power up
        logger.info("Waiting for camera to send token notification...")
        creds = await token_listener.wait_for_token(timeout=15)

        # We can disconnect BLE now with proper error handling
        logger.info("Token extracted. Disconnecting BLE...")
        await _disconnect_ble_safely(ble_client)
        ble_client = None

        logger.info(f"Success: Token: {creds['token'][:20]}...")
        logger.info(f"Success: Sequence from BLE: {creds['sequence'].hex()}")

        # PHASE 3: UDP LOGIN
        logger.info("="*60)
        logger.info("PHASE 3: UDP LOGIN")
        logger.info("="*60)

        logger.info("Waiting for WiFi connection...")
        wifi = WiFiManager()
        if not wifi.connect_to_camera_wifi():
            logger.error("Failed to connect to Camera WiFi. Exiting.")
            return

        # FIX #25: Critical timing fix
        # After BLE wakeup, camera's UDP stack needs time to initialize.
        # Official app (TrailCam Go) shows ~7-8 second delay before discovery succeeds.
        # Apply delay AFTER WiFi connected, BEFORE UDP discovery attempts.
        logger.info(f"[TIMING FIX #25] Waiting {config.CAMERA_STARTUP_DELAY}s for camera UDP stack initialization...")
        time.sleep(config.CAMERA_STARTUP_DELAY)
        logger.info(f"[TIMING FIX #25] Camera should now be ready for UDP discovery.")

        camera = CameraClient(CAMERA_IP, logger)
        camera.set_session_credentials(creds['token'], creds['sequence'])

        # Use connect_with_retries which includes discovery
        if camera.connect_with_retries():
            # Attempt standard login first
            if camera.login():
                logger.info("\n" + "SUCCESS "*10)
                logger.info("AUTHENTICATION SUCCESSFUL!")
                logger.info("SUCCESS "*10 + "\n")
            # Fallback to variant testing if standard login fails
            elif camera.try_all_variants():
                logger.info("\n" + "SUCCESS "*10)
                logger.info("AUTHENTICATION SUCCESSFUL (via fallback)!")
                logger.info("SUCCESS "*10 + "\n")
            else:
                logger.error("FAILED: Login failed with all variants")
                camera.close()
                return False

            # Keep alive for demonstration
            logger.info("Keeping session alive for 10s...")
            await asyncio.sleep(10)
            camera.close()
            return True
        else:
            logger.error("Failed to connect UDP socket (Discovery/Connection failed)")
            return False

    except asyncio.TimeoutError:
        logger.error("FAILED: Token extraction timeout")
        return False
    except Exception as e:
        logger.error(f"FAILED: Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Ensure BLE client is disconnected if something failed
        if ble_client and ble_client.is_connected:
            logger.info("Cleaning up BLE connection...")
            await _disconnect_ble_safely(ble_client)


async def _disconnect_ble_safely(client):
    """
    Safely disconnect BLE client with comprehensive error handling.
    
    Handles known issues with:
    - EOFError from dbus-fast on abnormal disconnects (Pi Zero 2W)
    - TimeoutError if camera killed connection
    - Incomplete reads when connection is already dead
    
    Args:
        client (BleakClient): The BLE client to disconnect
    """
    if not client:
        return
    
    try:
        if client.is_connected:
            await client.disconnect()
            logger.debug("BLE client disconnected successfully")
    except EOFError:
        # Known issue: dbus-fast unmarshaller gets EOFError when
        # camera or BLE stack kills connection abnormally
        logger.warning("BLE disconnect: Ignored EOFError (camera killed connection)")
    except asyncio.TimeoutError:
        # Connection timeout during disconnect
        logger.warning("BLE disconnect: Timeout - treating as disconnected")
    except asyncio.IncompleteReadError as e:
        # Connection broken mid-read
        logger.warning(f"BLE disconnect: Connection broken during read - {e}")
    except Exception as e:
        # Any other exception during disconnect
        logger.warning(f"BLE disconnect: Unexpected error (treating as safe) - {type(e).__name__}: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
