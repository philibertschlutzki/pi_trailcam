import asyncio
import logging
import struct
from bleak import BleakClient, BleakError
import config

class TokenListener:
    # Based on config.BLE_CHAR_UUID being ...0002..., we guess ...0003... for notification
    # This should be verified with ble_characteristic_scanner.py
    NOTIFICATION_CHAR_UUID = "00000003-0000-1000-8000-00805f9b34fb"

    def __init__(self, device_mac: str, logger=None, client=None):
        self.device_mac = device_mac
        self.logger = logger or logging.getLogger(__name__)
        self.client = client
        self.captured_data = None
        self.event = asyncio.Event()

    def _notification_handler(self, sender, data):
        """Callback for BLE notifications."""
        self.logger.debug(f"Received notification from {sender}: {data.hex()}")
        self.captured_data = data
        self.event.set()

    async def listen(self, timeout=10) -> dict:
        """
        Listen for BLE notification containing auth token.

        Returns:
            {"token": "I3mbwVIx...", "sequence": b'\x2b\x00\x00\x00'}

        Raises:
            asyncio.TimeoutError: If no notification within timeout
            BleakError: If BLE connection fails
        """
        if self.client and self.client.is_connected:
            self.logger.info(f"Using existing connection to {self.device_mac}...")
            return await self._listen_with_client(self.client, timeout)
        else:
            self.logger.info(f"Connecting to {self.device_mac} to listen for token...")
            async with BleakClient(self.device_mac, timeout=20.0) as client:
                return await self._listen_with_client(client, timeout)

    async def _listen_with_client(self, client, timeout):
        """
        Internal method to listen using a specific client instance.
        """
        if not client.is_connected:
            raise BleakError(f"Client is not connected to {self.device_mac}")

        self.logger.info(f"Subscribing to {self.NOTIFICATION_CHAR_UUID}...")

        try:
            await client.start_notify(self.NOTIFICATION_CHAR_UUID, self._notification_handler)
        except Exception as e:
            self.logger.error(f"Failed to start notify on {self.NOTIFICATION_CHAR_UUID}: {e}")
            raise BleakError(f"Could not subscribe to notification characteristic: {e}")

        self.logger.info("Waiting for notification...")
        try:
            await asyncio.wait_for(self.event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            self.logger.error("Token extraction timeout")
            # Cleanup subscription on timeout
            try:
                await client.stop_notify(self.NOTIFICATION_CHAR_UUID)
            except Exception as e:
                self.logger.warning(f"Failed to stop notify after timeout: {e}")
            raise

        # Cleanup subscription on success
        try:
            await client.stop_notify(self.NOTIFICATION_CHAR_UUID)
        except Exception as e:
             self.logger.warning(f"Failed to stop notify after success: {e}")

        return self._parse_payload(self.captured_data)

    def _parse_payload(self, data: bytes) -> dict:
        """
        Parse token and sequence from notification payload.
        Structure: [4 bytes: token_length] [4 bytes: sequence] [N bytes: token]
        """
        if not data:
            raise ValueError("Received empty data payload")

        if len(data) < 8:
            raise ValueError(f"Payload too short: {len(data)} bytes (expected > 8)")

        # Extract token_length (little-endian)
        token_len = struct.unpack("<I", data[0:4])[0]

        # Extract sequence bytes
        sequence = data[4:8]

        # Extract token
        # The token starts at byte 8.
        # Check if the data length matches expected length
        if len(data) < 8 + token_len:
            self.logger.warning(f"Data length {len(data)} < expected {8 + token_len}")

        token_bytes = data[8:8+token_len]

        # Decode as ASCII and strip nulls
        try:
            token_str = token_bytes.decode('ascii').rstrip('\x00')
        except UnicodeDecodeError:
            # Fallback if not pure ASCII, though it should be base64
            self.logger.warning("Token bytes are not valid ASCII, using replace")
            token_str = token_bytes.decode('ascii', errors='replace').rstrip('\x00')

        self.logger.debug(f"Raw BLE payload: {data.hex()}")
        self.logger.debug(f"Token length field: {token_len}")
        self.logger.debug(f"Sequence bytes: {sequence.hex()}")
        self.logger.info(f"✓ Token extracted: {token_str[:20]}... (len={len(token_str)})")

        if len(token_str) != 45:
            self.logger.warning(f"Token length {len(token_str)} != 45")

        return {
            "token": token_str,
            "sequence": sequence
        }
