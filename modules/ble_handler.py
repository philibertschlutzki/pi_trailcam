import asyncio
import logging
from bleak import BleakClient, BleakError
import config

# Setup logging
logger = logging.getLogger(__name__)

class BLEHandler:
    """
    Handles Bluetooth Low Energy (BLE) interactions with the Trail Camera.
    """

    def __init__(self):
        self.mac_address = config.BLE_MAC_ADDRESS
        self.char_uuid = config.CHAR_UUID
        self.payload = config.WAKEUP_PAYLOAD
        self.timeout = 20.0 # Timeout for connection attempts

    async def wake_camera(self, retries=3):
        """
        Connects to the camera via BLE and writes the magic packet to turn on WiFi.

        Args:
            retries (int): Number of times to retry the connection/write operation.

        Returns:
            bool: True if successful, False otherwise.
        """
        logger.info(f"Attempting to wake camera (MAC: {self.mac_address})...")

        for attempt in range(1, retries + 1):
            try:
                logger.debug(f"Connection attempt {attempt}/{retries}")

                async with BleakClient(self.mac_address, timeout=self.timeout) as client:
                    if not client.is_connected:
                        logger.error("Failed to connect to BLE device.")
                        continue

                    logger.info("BLE Connected. Sending magic packet...")

                    # Write the payload to the characteristic
                    # response=True ensures we wait for an acknowledgment (Write Request vs Write Command)
                    # Adjust response=False if the protocol uses 'Write Command' (No Ack)
                    await client.write_gatt_char(self.char_uuid, self.payload, response=True)

                    logger.info("Magic packet sent successfully.")

                    # Some cameras might need a moment or a disconnect to trigger the action
                    await asyncio.sleep(1)

                logger.info("BLE Disconnected. Wakeup sequence complete.")
                return True

            except BleakError as e:
                logger.error(f"BLE Error on attempt {attempt}: {e}")
                await asyncio.sleep(2) # Wait a bit before retrying
            except Exception as e:
                logger.exception(f"Unexpected error during BLE wakeup: {e}")
                return False

        logger.error("All BLE wakeup attempts failed.")
        return False
