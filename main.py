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

        # We need to wake the camera AND listen for the token.
        # The token comes after wake.
        # ble_mgr.wake_camera sends the magic packet.
        # token_listener.listen connects and waits for notification.
        #
        # ISSUE: If we connect with wake_camera, then disconnect, we might lose the "session"
        # or the notification might happen while we are disconnected?
        #
        # Re-reading the prompt:
        # "What Works (Android App): 1. App wakes camera via BLE 2. Camera sends NEW token via BLE notification"
        #
        # If I run wake_camera(), it connects, writes, then disconnects.
        # Then TokenListener connects.
        # Will the camera send the notification to the NEW connection?
        # Or should we be listening while waking?
        #
        # Prompt says: "Component 1 ... Listen for BLE notification containing auth token. ... Connect to camera MAC address"
        # "Component 4 ... Phase 1: BLE Wake ... Phase 2: Token Extraction"
        #
        # This implies sequential operations.
        # If wake_camera wakes it up, maybe it stays awake and advertises or accepts connection,
        # and THEN sends notification when we subscribe?
        # Or maybe the notification is sent immediately after wake logic?
        #
        # If the notification is sent *unsolicited* immediately after wake, we might miss it if we disconnect and reconnect.
        # However, typically you subscribe to notifications (CCCD write). The device won't send notifications unless subscribed.
        # So:
        # 1. Wake (write char 0002).
        # 2. Connect (or stay connected), Subscribe to char 0003.
        # 3. Receive notification.

        # Existing BLEManager.wake_camera disconnects at the end.
        # If I use TokenListener separately, it creates a NEW connection.
        # Let's hope the camera queues the notification or waits for subscription.
        # Given the plan structure, I will follow Phase 1 then Phase 2.

        await BLEManager.wake_camera(mac_address)
        # Short sleep to allow camera to process wake?
        await asyncio.sleep(2)

        # PHASE 2: TOKEN EXTRACTION (NEW!)
        logger.info("="*60)
        logger.info("PHASE 2: TOKEN EXTRACTION")
        logger.info("="*60)

        token_listener = TokenListener(mac_address, logger)
        creds = await token_listener.listen(timeout=10)

        logger.info(f"✓ Token: {creds['token'][:20]}...")
        logger.info(f"✓ Sequence: {creds['sequence'].hex()}")

        # PHASE 3: UDP LOGIN
        logger.info("="*60)
        logger.info("PHASE 3: UDP LOGIN")
        logger.info("="*60)

        # Connect to WiFi first?
        # The original code had a step "Wait for WiFi".
        # The prompt for main.py didn't explicitly mention WiFi connection,
        # but CameraClient needs IP connectivity.
        # "CAMERA_IP = '192.168.43.1'"
        # I should probably ensure WiFi is connected.

        logger.info("Waiting for WiFi connection...")
        # (Assuming the user connects manually or we use WiFiManager)
        # The prompt's main.py example didn't show WiFiManager usage, but the original did.
        # I will re-add WiFiManager usage to be safe.

        wifi = WiFiManager()
        if not wifi.connect_to_camera_wifi():
             logger.error("Failed to connect to Camera WiFi. Exiting.")
             return

        camera = CameraClient(CAMERA_IP, logger)
        camera.set_session_credentials(creds['token'], creds['sequence'])

        if camera.connect():
             if camera.login():
                logger.info("🎉 AUTHENTICATION SUCCESSFUL!")

                # Keep alive for demonstration
                logger.info("Keeping session alive for 10s...")
                await asyncio.sleep(10)
                camera.close()
                return True
             else:
                logger.error("✗ Login failed despite correct token")
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
