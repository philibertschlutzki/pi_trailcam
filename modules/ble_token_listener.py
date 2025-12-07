import asyncio
import logging
import struct
from bleak import BleakClient, BleakError
import config

class TokenListener:
    # Based on config.BLE_CHAR_UUID being ...0002..., we guess ...0003... for notification
    # This should be verified with ble_characteristic_scanner.py
    NOTIFICATION_CHAR_UUID = "00000003-0000-1000-8000-00805f9b34fb"
    
    # Known token size from camera protocol (base64 encoded with padding)
    EXPECTED_TOKEN_LENGTH = 45
    # Minimum valid token in first packet (at least token_len + 8 bytes header)
    MIN_VALID_PACKET_SIZE = 12

    def __init__(self, device_mac: str, logger=None, client=None):
        self.device_mac = device_mac
        self.logger = logger or logging.getLogger(__name__)
        self.client = client
        self.captured_data = b''
        self.event = asyncio.Event()
        self.fragment_timeout = 2.0  # Wait max 2s for next fragment

    def _notification_handler(self, sender, data):
        """
        Callback for BLE notifications.
        
        Handles fragmented token data:
        - Concatenates multiple notifications
        - Detects complete token based on length field
        - Sets event when complete
        """
        self.logger.debug(f"Received notification from {sender}: {data.hex()} (len={len(data)})")
        
        # Append to buffer
        self.captured_data += data
        
        # Try to parse what we have so far
        if self._is_token_complete():
            self.logger.debug("Token assembly complete, signaling event")
            self.event.set()

    def _is_token_complete(self) -> bool:
        """
        Check if we have received the complete token.
        
        Token structure:
        - Bytes 0-3: token length (little-endian uint32)
        - Bytes 4-7: sequence (4 bytes)
        - Bytes 8+: token data (variable length based on length field)
        
        Returns:
            True if we have at least (8 + token_len) bytes
        """
        if len(self.captured_data) < 8:
            return False
        
        # Parse token length from header
        try:
            token_len = struct.unpack("<I", self.captured_data[0:4])[0]
        except struct.error:
            return False
        
        # Check if we have all data: 8 bytes header + token_len bytes
        expected_total = 8 + token_len
        has_complete = len(self.captured_data) >= expected_total
        
        if has_complete:
            self.logger.debug(f"Token complete: {len(self.captured_data)} >= {expected_total}")
        
        return has_complete

    async def listen(self, timeout=10) -> dict:
        """
        Listen for BLE notification containing auth token.

        Returns:
            {"token": "I3mbwVIx...", "sequence": b'\x2b\x00\x00\x00'}

        Raises:
            asyncio.TimeoutError: If no complete token within timeout
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

        self.logger.info("Waiting for notification (may be fragmented)...")
        try:
            # Wait for token to be complete (handles fragmentation automatically)
            await asyncio.wait_for(self.event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            self.logger.error(f"Token extraction timeout. Received {len(self.captured_data)} bytes so far.")
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
        Parse token and sequence from complete notification payload.
        Structure: [4 bytes: token_length] [4 bytes: sequence] [N bytes: token]
        """
        if not data:
            raise ValueError("Received empty data payload")

        if len(data) < 8:
            raise ValueError(f"Payload too short: {len(data)} bytes (expected >= 8)")

        # Extract token_length (little-endian)
        token_len = struct.unpack("<I", data[0:4])[0]

        # Extract sequence bytes
        sequence = data[4:8]

        # Extract token
        # The token starts at byte 8.
        if len(data) < 8 + token_len:
            # This should NOT happen anymore due to _is_token_complete()
            self.logger.error(f"FATAL: Data length {len(data)} < expected {8 + token_len}")
            raise ValueError(f"Incomplete token data: {len(data)} < {8 + token_len}")

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
        self.logger.info(f"Success: Token extracted: {token_str[:20]}... (len={len(token_str)})")

        # Validate token length matches expected
        if len(token_str) != self.EXPECTED_TOKEN_LENGTH:
            self.logger.warning(f"Token length {len(token_str)} != {self.EXPECTED_TOKEN_LENGTH}")
            # Don't fail, camera might use different encoding
            # Just warn for debugging
        
        # Validate token is not empty
        if not token_str or token_str == '':
            raise ValueError("Extracted token is empty")

        return {
            "token": token_str,
            "sequence": sequence
        }
