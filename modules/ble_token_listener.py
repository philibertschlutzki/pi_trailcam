import asyncio
import logging
import struct
import json
from bleak import BleakClient, BleakError
import config

class TokenListener:
    # Based on config.BLE_CHAR_UUID being ...0002..., we guess ...0003... for notification
    # This should be verified with ble_characteristic_scanner.py
    NOTIFICATION_CHAR_UUID = "00000003-0000-1000-8000-00805f9b34fb"
    
    # FIX #26: Corrected token size expectations
    # Actual camera sends 80 bytes total (8 header + 72 token)
    # NOT 87835 bytes as previously expected
    EXPECTED_TOKEN_LENGTHS = (45, 72, 80)  # Accept 45, 72 bytes, or 80 total
    # Minimum valid packet: 8 bytes header + at least 45 bytes token
    MIN_VALID_PACKET_SIZE = 53  # 8 + 45
    # Maximum valid packet: 8 bytes header + max 72 bytes token
    MAX_VALID_PACKET_SIZE = 80  # 8 + 72

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
        - Logs detailed information for debugging
        
        FIX #26: Accept 80+ bytes as complete (not 87k+)
        """
        self.logger.info(f"[NOTIFICATION] Received {len(data)} bytes from {sender}")
        self.logger.debug(f"  Hex: {data.hex()}")
        
        # Append to buffer
        self.captured_data += data
        
        total_bytes = len(self.captured_data)
        self.logger.debug(f"  Total accumulated: {total_bytes} bytes")
        
        # Check if token is complete
        if self._is_token_complete():
            # Get expected length for logging
            if total_bytes >= 4:
                try:
                    token_len = struct.unpack("<I", self.captured_data[0:4])[0]
                    expected_total = 8 + token_len
                    self.logger.info(
                        f"[NOTIFICATION] Token is complete! "
                        f"({total_bytes} bytes total, length field says {token_len}, expected {expected_total})"
                    )
                except struct.error:
                    self.logger.info(f"[NOTIFICATION] Token is complete! ({total_bytes} bytes total)")
            else:
                self.logger.info(f"[NOTIFICATION] Token is complete! ({total_bytes} bytes total)")
            self.event.set()
        else:
            # Log how many more bytes we need
            if total_bytes >= 4:
                try:
                    token_len = struct.unpack("<I", self.captured_data[0:4])[0]
                    expected_total = 8 + token_len
                    remaining = expected_total - total_bytes
                    self.logger.debug(
                        f"  Token not yet complete: {total_bytes}/{expected_total} bytes "
                        f"(waiting for {remaining} more, token_len={token_len})"
                    )
                except Exception as e:
                    self.logger.debug(f"  Token not yet complete: {total_bytes} bytes received")
            else:
                self.logger.debug(f"  Token not yet complete: {total_bytes} bytes received")

    def _is_token_complete(self) -> bool:
        """
        Check if we have received the complete token.
        
        FIX #26: Handle variable-length tokens correctly.
        
        Token structure (Variable length):
        - Bytes 0-3: token length (little-endian uint32)
        - Bytes 4-7: sequence (4 bytes)
        - Bytes 8+: token data (variable length based on length field)
        
        Size detection (Fallback):
        - If we have 53+ bytes, likely complete (45 byte token + 8 header)
        - If we have 80+ bytes, definitely complete (72 byte token + 8 header)
        
        Returns:
            True if we have received the complete token
        """
        total = len(self.captured_data)
        
        # Need at least 8 bytes for header
        if total < 8:
            return False
        
        # FIX #26: Try to parse token_len, but also have fallback
        try:
            token_len = struct.unpack("<I", self.captured_data[0:4])[0]
            
            # FIX #26: Accept reasonable token lengths
            # Real camera sends tokens around 45-72 bytes
            # Allow up to 100 bytes for safety margin
            if 45 <= token_len <= 100:
                expected_total = 8 + token_len
                has_complete = total >= expected_total
                
                if has_complete:
                    self.logger.debug(
                        f"Token complete (length-based): {total} >= {expected_total} "
                        f"(token_len={token_len})"
                    )
                
                return has_complete
            else:
                # Token length is unreasonable, use size-based fallback
                self.logger.debug(
                    f"Token length field suspicious: {token_len}. "
                    f"Falling back to size-based detection (total={total})"
                )
                return self._is_token_complete_by_size(total)
            
        except struct.error as e:
            self.logger.debug(f"Failed to parse token_len: {e}")
            # Fallback to size-based detection
            return self._is_token_complete_by_size(total)
    
    def _is_token_complete_by_size(self, total: int) -> bool:
        """
        Fallback: Detect token completion by total size.
        
        Expected sizes:
        - 53 bytes: 45-byte token + 8-byte header (minimum)
        - 80 bytes: 72-byte token + 8-byte header (typical/most common)
        
        FIX #26: Accept 80 bytes as complete (this is what real camera sends)
        
        Args:
            total: Total accumulated bytes
            
        Returns:
            True if size suggests token is complete
        """
        # If we have 80 bytes or more, token is definitely complete
        if total >= 80:
            self.logger.debug(
                f"Token complete (size-based): {total} >= 80 bytes (typical camera token)"
            )
            return True
        
        # If we have 53+ bytes, likely complete
        if total >= 53:
            self.logger.debug(
                f"Token likely complete (size-based): {total} >= 53 bytes (minimum)"
            )
            return True
        
        return False

    # FIX #18: Split into two methods to prevent race condition
    async def start_listening(self):
        """
        Register notification handler IMMEDIATELY.
        
        This must be called BEFORE the camera sends token data.
        Call this right after BLE wake, before waiting for token.
        
        This prevents race condition where:
        - Old: Register handler → Wait (but camera already sent data)
        - New: Register handler first (ready to receive) → Then wait
        
        Raises:
            BleakError: If client not connected or subscription fails
        """
        if not self.client or not self.client.is_connected:
            raise BleakError(f"Client is not connected to {self.device_mac}")
        
        self.logger.info(f"Subscribing to {self.NOTIFICATION_CHAR_UUID}...")
        
        try:
            await self.client.start_notify(
                self.NOTIFICATION_CHAR_UUID,
                self._notification_handler
            )
        except Exception as e:
            self.logger.error(f"Failed to start notify on {self.NOTIFICATION_CHAR_UUID}: {e}")
            raise BleakError(f"Could not subscribe to notification characteristic: {e}")
        
        self.logger.info("[HANDLER] Notification handler registered and ready to receive.")

    async def wait_for_token(self, timeout=15) -> dict:
        """
        Wait for token notification to arrive.
        
        This must be called AFTER start_listening().
        
        Args:
            timeout: Maximum time to wait in seconds (default 15s).
                     Increased from 10s because camera needs time to power up
                     and send token after magic packet.
        
        Returns:
            {"token": "...", "sequence": b'...'}
        
        Raises:
            asyncio.TimeoutError: If no complete token within timeout
        """
        self.logger.info("Waiting for token notification from camera...")
        
        try:
            # Wait for handler to receive complete token
            await asyncio.wait_for(self.event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            bytes_received = len(self.captured_data)
            self.logger.error(
                f"Token extraction timeout. "
                f"Received {bytes_received} bytes so far (expected at least 53 bytes)."
            )
            if bytes_received > 0:
                self.logger.error(
                    f"Raw data (hex): {self.captured_data.hex()}"
                )
            # Try to cleanup subscription
            try:
                if self.client and self.client.is_connected:
                    await self.client.stop_notify(self.NOTIFICATION_CHAR_UUID)
            except Exception as e:
                self.logger.warning(f"Failed to stop notify after timeout: {e}")
            raise
        
        # Cleanup subscription on success
        try:
            if self.client and self.client.is_connected:
                await self.client.stop_notify(self.NOTIFICATION_CHAR_UUID)
        except Exception as e:
            self.logger.warning(f"Failed to stop notify after success: {e}")
        
        return self._parse_payload(self.captured_data)

    async def listen(self, timeout=10) -> dict:
        """
        Legacy method: Listen for BLE notification containing auth token.
        
        This method combines start_listening() and wait_for_token().
        Use start_listening() + wait_for_token() instead for better control.
        
        Returns:
            {"token": "I3mbwVIx...", "sequence": b'\x2b\x00\x00\x00'}

        Raises:
            asyncio.TimeoutError: If no complete token within timeout
            BleakError: If BLE connection fails
        """
        if self.client and self.client.is_connected:
            self.logger.info(f"Using existing connection to {self.device_mac}...")
            await self.start_listening()
            return await self.wait_for_token(timeout=timeout)
        else:
            self.logger.info(f"Connecting to {self.device_mac} to listen for token...")
            async with BleakClient(self.device_mac, timeout=20.0) as client:
                self.client = client
                await self.start_listening()
                return await self.wait_for_token(timeout=timeout)

    async def _listen_with_client(self, client, timeout):
        """
        Internal method to listen using a specific client instance.
        (Kept for backward compatibility, but not used in new code)
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
        
        FIX #20: Support both raw tokens and JSON-wrapped tokens.
        FIX #26: Handle variable-length tokens correctly (80 bytes typical)
        
        Structures supported:
        1. Raw format: [4 bytes: token_length] [4 bytes: sequence] [N bytes: token]
        2. JSON format: [4 bytes: json_length] [4 bytes: sequence] [JSON string with token field]
        
        JSON Parsing Logic:
        - Detects JSON format by checking for '{' and '}' characters.
        - Parses the JSON string to extract the actual token.
        - Checks multiple candidate fields: `token`, `data`, `key`, `auth_token`, `access_token`.
        - Prioritizes 'token' field if present.
        - Fallback: Uses full JSON string if no specific field found.

        Why JSON?
        Newer firmware versions wrap the token in JSON to include additional metadata
        (like SSID, return codes) which provides context for the connection.

        See PROTOCOL_ANALYSIS.md for detailed token context.
        
        FIX #26: Support 80-byte tokens (most common from camera)
        """
        if not data:
            raise ValueError("Received empty data payload")

        if len(data) < 8:
            raise ValueError(f"Payload too short: {len(data)} bytes (expected >= 8)")

        # Extract token_length (little-endian)
        try:
            token_len = struct.unpack("<I", data[0:4])[0]
        except struct.error as e:
            self.logger.error(f"Failed to parse token_len: {e}")
            # FIX #26: If we have 80 bytes, assume it's a complete token
            if len(data) >= 80:
                token_len = len(data) - 8  # Treat remainder as token
                self.logger.warning(f"Using fallback token_len: {token_len} (from 80-byte packet)")
            else:
                # Try 72-byte token as default
                token_len = 72
                self.logger.warning(f"Using fallback token_len: {token_len}")

        # Extract sequence bytes
        sequence = data[4:8]

        # Extract token data
        actual_data_length = len(data) - 8
        if actual_data_length < token_len:
            self.logger.warning(
                f"Data length {actual_data_length} < expected {token_len}. "
                f"Using available {actual_data_length} bytes."
            )
            token_bytes = data[8:]
        else:
            token_bytes = data[8:8+token_len]

        # Decode as ASCII and strip nulls
        try:
            token_str = token_bytes.decode('ascii').rstrip('\x00')
            
            # FIX #20: Check if it's JSON and parse it
            if token_str.startswith('{') and '}' in token_str:
                self.logger.info(f"[PARSE] Detected JSON token format")
                try:
                    token_json = json.loads(token_str)
                    self.logger.debug(f"[PARSE] Parsed JSON: {json.dumps(token_json, indent=2)[:200]}...")
                    
                    # Extract the actual token from common field names
                    actual_token = None
                    for field_name in ['token', 'data', 'key', 'auth_token', 'access_token']:
                        if field_name in token_json:
                            actual_token = token_json[field_name]
                            self.logger.info(f"[PARSE] Extracted token from field '{field_name}'")
                            break
                    
                    if actual_token:
                        token_str = str(actual_token)
                        self.logger.info(f"[PARSE] Using extracted token (length: {len(token_str)})")
                    else:
                        self.logger.warning(
                            f"[PARSE] JSON has no recognized token field. "
                            f"Available keys: {list(token_json.keys())}. "
                            f"Using entire JSON as token."
                        )
                        # Try to use the entire JSON string as token
                        token_str = json.dumps(token_json)
                        
                except json.JSONDecodeError as e:
                    self.logger.warning(
                        f"[PARSE] Failed to parse JSON token: {e}. "
                        f"Using raw string as token."
                    )
            else:
                self.logger.debug(f"[PARSE] Token is not JSON, using raw format")
                    
        except UnicodeDecodeError:
            # Fallback if not pure ASCII, though it should be base64
            self.logger.warning("[PARSE] Token bytes are not valid ASCII, using replace")
            token_str = token_bytes.decode('ascii', errors='replace').rstrip('\x00')

        self.logger.debug(f"Raw BLE payload: {data.hex()}")
        self.logger.debug(f"Token length field: {token_len}")
        self.logger.debug(f"Sequence bytes: {sequence.hex()}")
        self.logger.info(f"Success: Token extracted: {token_str[:20]}... (len={len(token_str)})")

        # FIX #26: More lenient token length validation
        # Accept tokens in expected range without warning
        if not token_str.startswith('{'):
            if len(token_str) not in self.EXPECTED_TOKEN_LENGTHS:
                # Only warn if dramatically outside range
                if len(token_str) < 40 or len(token_str) > 150:
                    self.logger.warning(
                        f"Token length {len(token_str)} is unusual (expected 45/72/80). "
                        f"This might indicate an encoding issue."
                    )
        
        # Validate token is not empty
        if not token_str or token_str == '':
            raise ValueError("Extracted token is empty")

        return {
            "token": token_str,
            "sequence": sequence
        }
