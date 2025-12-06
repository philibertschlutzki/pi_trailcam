import asyncio
import logging
from bleak import BleakClient, BleakScanner
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def discover_token_characteristic(device_mac: str):
    """
    Scan camera and list all BLE characteristics.

    Purpose: Find which characteristic UUID sends the token.
    """
    logger.info(f"Connecting to {device_mac}...")

    try:
        async with BleakClient(device_mac, timeout=20.0) as client:
            logger.info(f"Connected to {device_mac}")

            logger.info("Discovering services...")
            for service in client.services:
                logger.info(f"Service: {service.uuid} ({service.description})")

                for char in service.characteristics:
                    props = ", ".join(char.properties)
                    logger.info(f"  Characteristic: {char.uuid} ({char.description})")
                    logger.info(f"    Properties: {props}")

                    if "notify" in char.properties:
                        logger.info(f"    -> CANDIDATE FOR NOTIFICATION (Token source?)")

            logger.info("Discovery complete.")

    except Exception as e:
        logger.error(f"Error during discovery: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ble_characteristic_scanner.py <MAC_ADDRESS>")
        sys.exit(1)

    mac_address = sys.argv[1]
    asyncio.run(discover_token_characteristic(mac_address))
