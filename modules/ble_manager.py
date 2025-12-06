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
                #      return d.address

            logger.warning("No camera found during BLE scan.")
            return None
        except Exception as e:
            logger.error(f"BLE Scan failed: {e}")
            return None

    @staticmethod
    async def wake_camera(mac_address, retries=3):
        """
        Connects to the camera via BLE and writes the magic packet to turn on WiFi.
        Uses manual connection handling to avoid EOFError on Pi Zero 2W.
        """
        logger.info(f"Attempting to wake camera (MAC: {mac_address})...")

        for attempt in range(1, retries + 1):
            client = None
            try:
                logger.debug(f"Connection attempt {attempt}/{retries}")
                
                # Instanzieren ohne Context Manager (kein 'async with')
                client = BleakClient(mac_address, timeout=20.0)
                
                # 1. Manuelles Verbinden
                await client.connect()

                if not client.is_connected:
                    logger.error("Failed to connect to BLE device (is_connected=False).")
                    continue

                logger.info("BLE Connected. Sending magic packet...")

                # 2. Schreiben
                # HINWEIS: response=True ist Standard, kann aber bei Timeouts zu Problemen führen.
                # Falls es hakt, versuche hier response=False.
                await client.write_gatt_char(config.BLE_CHAR_UUID, config.BLE_PAYLOAD, response=True)

                logger.info("Magic packet sent successfully.")

                # 3. Warten (Wichtig für Buffer)
                await asyncio.sleep(1.0)
                
                logger.info("BLE operation successful.")
                return True

            except BleakError as e:
                logger.error(f"BLE Error on attempt {attempt}: {e}")
                # Kurze Pause vor dem nächsten Versuch
                await asyncio.sleep(2)
            
            except Exception as e:
                logger.exception(f"Unexpected error during BLE wakeup: {e}")
                # Bei unerwarteten Fehlern brechen wir oft besser ab oder versuchen es erneut
                # Hier: weiter zum nächsten Versuch nach Pause
                await asyncio.sleep(2)

            finally:
                # 4. Sicheres, manuelles Trennen
                # Dieser Block fängt den EOFError ab, der den Pi zum Absturz bringt
                if client:
                    try:
                        # Wir prüfen, ob wir überhaupt disconnecten müssen
                        if client.is_connected:
                            await client.disconnect()
                    except (EOFError, asyncio.IncompleteReadError):
                        # DAS IST DER FIX:
                        logger.warning("Ignored expected EOFError/IncompleteRead during disconnect (Camera likely killed connection).")
                    except Exception as e:
                        logger.warning(f"Minor error during disconnect cleanup: {e}")

        logger.error("All BLE wakeup attempts failed.")
        return False
