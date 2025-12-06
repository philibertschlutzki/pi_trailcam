import asyncio
import logging
from bleak import BleakClient, BleakScanner, BleakError
import config

logger = logging.getLogger(__name__)

class BLEManager:
    """
    Handles Bluetooth Low Energy (BLE) interactions with the KJK230 Trail Camera.
    """

    @staticmethod
    async def scan_for_camera(timeout=10.0):
        """
        Scans for a BLE device with a name starting with the configured prefix or characteristic.
        Returns the MAC address if found, else None.
        """
        logger.info("Scanning for KJK Camera via BLE...")
        try:
            devices = await BleakScanner.discover(timeout=timeout)
            for d in devices:
                # Check by Name
                if d.name and (d.name.startswith("KJK") or d.name.startswith("Trail")):
                    logger.info(f"Found Device by Name: {d.name} ({d.address})")
                    return d.address

                # Ideally we would check for Service UUIDs, but sometimes advertisement data is limited.
                # If we had the service UUID in advertisement data:
                # if config.BLE_SERVICE_UUID.lower() in [u.lower() for u in d.metadata.get("uuids", [])]:
                #     return d.address

            logger.warning("No camera found during BLE scan.")
            return None
        except Exception as e:
            logger.error(f"BLE Scan failed: {e}")
            return None

    @staticmethod
    async def wake_camera(mac_address, retries=3):
        """
        Connects to the camera via BLE and writes the magic packet to turn on WiFi.

        Args:
            mac_address (str): The BLE MAC address.
            retries (int): Number of times to retry the connection/write operation.

        Returns:
            bool: True if successful, False otherwise.
        """
        logger.info(f"Attempting to wake camera (MAC: {mac_address})...")

        for attempt in range(1, retries + 1):
            try:
                logger.debug(f"Connection attempt {attempt}/{retries}")

                async with BleakClient(mac_address, timeout=20.0) as client:
                    if not client.is_connected:
                        logger.error("Failed to connect to BLE device.")
                        continue

                    logger.info("BLE Connected. Sending magic packet...")

                    # Write the payload to the characteristic
                    await client.write_gatt_char(config.BLE_CHAR_UUID, config.BLE_PAYLOAD, response=True)

                    logger.info("Magic packet sent successfully.")

                    # Wait briefly before disconnecting to ensure processing
                    await asyncio.sleep(1)

                logger.info("BLE Disconnected. Wakeup sequence complete.")
                return True

            except BleakError as e:
                logger.error(f"BLE Error on attempt {attempt}: {e}")
                await asyncio.sleep(2)
            except Exception as e:
                logger.exception(f"Unexpected error during BLE wakeup: {e}")
                return False

        logger.error("All BLE wakeup attempts failed.")
        return False
