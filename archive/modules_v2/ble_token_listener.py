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
                        f"[NOTIFICATION] Packet is complete! "
                        f"({total_bytes} bytes total, length field says {token_len}, expected {expected_total})"
                    )
                except struct.error:
                    self.logger.info(f"[NOTIFICATION] Packet is complete! ({total_bytes} bytes total)")
            else:
                self.logger.info(f"[NOTIFICATION] Packet is complete! ({total_bytes} bytes total)")
            self.event.set()
        else:
            # Log how many more bytes we need
            if total_bytes >= 4:
                try:
                    token_len = struct.unpack("<I", self.captured_data[0:4])[0]
                    expected_total = 8 + token_len
                    remaining = expected_total - total_bytes
                    self.logger.debug(
                        f"  Packet not yet complete: {total_bytes}/{expected_total} bytes "
                        f"(waiting for {remaining} more, token_len={token_len})"
                    )
                except Exception as e:
                    self.logger.debug(f"  Packet not yet complete: {total_bytes} bytes received")
            else:
                self.logger.debug(f"  Packet not yet complete: {total_bytes} bytes received")

    def _is_token_complete(self) -> bool:
        """
        Check if we have received the complete token.
        
        FIX #26: Handle variable-length tokens correctly.
        """
        total = len(self.captured_data)
        
        # Need at least 8 bytes for header
        if total < 8:
            return False
        
        # FIX #26: Try to parse token_len, but also have fallback
        try:
            token_len = struct.unpack("<I", self.captured_data[0:4])[0]
            
            # FIX #26: Accept reasonable token lengths
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
                # Token length is unreasonable (e.g., might be a small JSON packet with wifi info)
                # If length is small (e.g. < 100), it might be a valid JSON packet even if not the token we want.
                # We trust the length field if it matches the data we have.
                if token_len < 1000:
                    expected_total = 8 + token_len
                    if total >= expected_total:
                         self.logger.debug(f"Small packet complete: {total} >= {expected_total}")
                         return True

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

    async def start_listening(self):
        """
        Register notification handler IMMEDIATELY.
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
        
        FIX: Loop to ignore packets that only contain WiFi info ('pwd') but no 'token'.
        """
        self.logger.info("Waiting for token notification from camera...")
        
        start_time = asyncio.get_event_loop().time()
        
        while (asyncio.get_event_loop().time() - start_time) < timeout:
            try:
                # Calculate remaining time
                remaining = timeout - (asyncio.get_event_loop().time() - start_time)
                if remaining <= 0:
                    break

                # Wait for handler to receive complete packet
                await asyncio.wait_for(self.event.wait(), timeout=remaining)

                # Check what we got
                parsed = self._parse_payload(self.captured_data)

                if parsed:
                    return parsed

                # If we got here, it means we parsed a packet but it wasn't the TOKEN.
                # It was likely the WiFi info packet.
                # Reset and continue waiting.
                self.logger.info("[PARSE] Received packet with no token. Resetting buffer and waiting for next packet...")
                self.captured_data = b''
                self.event.clear()

            except asyncio.TimeoutError:
                break
            except Exception as e:
                self.logger.error(f"Error during token wait: {e}")
                # Don't break immediately, maybe retry?
                # But if parsing failed badly, maybe we should stop.
                # For now, let's break to avoid infinite loops on hard errors.
                break

        # If we exit loop without returning
        bytes_received = len(self.captured_data)
        self.logger.error(
            f"Token extraction timeout. "
            f"Received {bytes_received} bytes in buffer."
        )
        if bytes_received > 0:
            self.logger.error(
                f"Raw data (hex): {self.captured_data.hex()}"
            )

        # Cleanup
        try:
            if self.client and self.client.is_connected:
                await self.client.stop_notify(self.NOTIFICATION_CHAR_UUID)
        except Exception:
            pass

        raise asyncio.TimeoutError("Failed to extract valid token")

    def _parse_payload(self, data: bytes) -> dict:
        """
        Parse token and sequence from complete notification payload.
        
        FIX #78:
        - Strict check for 'token' field.
        - DO NOT fallback to 'pwd' field.
        - Return None if token is missing (so wait_for_token can continue).
        """
        if not data:
            return None

        if len(data) < 8:
            return None

        # Extract token_length (little-endian)
        try:
            token_len = struct.unpack("<I", data[0:4])[0]
        except struct.error:
            token_len = len(data) - 8

        # Extract sequence bytes
        sequence = data[4:8]

        # Extract token data
        actual_data_length = len(data) - 8
        if actual_data_length < token_len:
             token_bytes = data[8:]
        else:
             token_bytes = data[8:8+token_len]

        token_str = ""
        # Decode as ASCII and strip nulls
        try:
            token_str = token_bytes.decode('ascii').rstrip('\x00')
            
            # Check for JSON
            if token_str.startswith('{') and '}' in token_str:
                self.logger.info(f"[PARSE] Detected JSON payload")
                try:
                    token_json = json.loads(token_str)
                    self.logger.debug(f"[PARSE] JSON Content: {json.dumps(token_json, indent=2)[:200]}...")
                    
                    actual_token = None

                    # PRIMARY: Check for 'token' field (Session Token)
                    if 'token' in token_json:
                        actual_token = token_json['token']
                        self.logger.info(f"[PARSE] ✓ Found 'token' field: {str(actual_token)[:10]}...")
                    
                    # LOGGING ONLY for pwd
                    if 'pwd' in token_json:
                        self.logger.info(f"[PARSE] Found 'pwd' (WiFi Password): {token_json['pwd']}")
                        if not actual_token:
                            self.logger.warning("[PARSE] Packet contains 'pwd' but NO 'token'. Ignoring as auth token.")

                    if actual_token:
                        token_str = str(actual_token)
                        return {
                            "token": token_str,
                            "sequence": sequence
                        }
                    else:
                        # Valid JSON but no token found. Return None to signal "keep waiting"
                        return None
                        
                except json.JSONDecodeError:
                    self.logger.warning(f"[PARSE] Failed to parse JSON. Raw: {token_str}")
            else:
                self.logger.debug(f"[PARSE] Payload is not JSON. Using raw string.")
                    
        except UnicodeDecodeError:
            self.logger.warning("[PARSE] Payload bytes are not valid ASCII.")
            token_str = token_bytes.decode('ascii', errors='replace').rstrip('\x00')

        # If not JSON, or JSON parsing failed, check if we have a raw token string
        # BUT only if it looks like a token (length check)
        if len(token_str) > 20: # Arbitrary min length for a token
             self.logger.info(f"[PARSE] Using raw string as token (len={len(token_str)})")
             return {
                "token": token_str,
                "sequence": sequence
             }
        
        self.logger.warning("[PARSE] Payload does not contain a valid token.")
        return None
