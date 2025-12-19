
import asyncio
import unittest
import struct
import json
from unittest.mock import MagicMock
from modules.ble_token_listener import TokenListener

class TestBLETokenListener(unittest.TestCase):
    def setUp(self):
        self.listener = TokenListener("00:00:00:00:00:00")
        self.listener.logger = MagicMock()

    def test_json_parsing_priority_token_field(self):
        # Construct a fake BLE notification payload with both 'pwd' and 'token'
        json_data = {
            "ret": 0,
            "ssid": "TestSSID",
            "pwd": "85087127", # The WiFi password
            "token": "MzlB36X/IVo8ZzI5rG9j1w==" # The REAL token
        }
        json_str = json.dumps(json_data)
        token_bytes = json_str.encode('ascii') + b'\x00'
        token_len = len(token_bytes)

        # Create payload
        payload = struct.pack("<I", token_len)
        payload += b'\x01\x00\x00\x00'
        payload += token_bytes

        # Parse
        result = self.listener._parse_payload(payload)

        # Verify that 'token' field is preferred
        self.assertEqual(result['token'], "MzlB36X/IVo8ZzI5rG9j1w==")

    def test_json_parsing_fallback_pwd(self):
        # Construct a fake BLE notification payload with only 'pwd'
        json_data = {
            "ret": 0,
            "ssid": "TestSSID",
            "pwd": "85087127"
        }
        json_str = json.dumps(json_data)
        token_bytes = json_str.encode('ascii') + b'\x00'
        token_len = len(token_bytes)

        # Create payload
        payload = struct.pack("<I", token_len)
        payload += b'\x01\x00\x00\x00'
        payload += token_bytes

        # Parse
        result = self.listener._parse_payload(payload)

        # Verify that it falls back to 'pwd'
        self.assertEqual(result['token'], "85087127")

    def test_json_parsing_fallback_other(self):
        # Construct a fake BLE notification payload with 'access_token'
        json_data = {
            "access_token": "some_token_value"
        }
        json_str = json.dumps(json_data)
        token_bytes = json_str.encode('ascii') + b'\x00'
        token_len = len(token_bytes)

        # Create payload
        payload = struct.pack("<I", token_len)
        payload += b'\x01\x00\x00\x00'
        payload += token_bytes

        # Parse
        result = self.listener._parse_payload(payload)

        # Verify that it falls back
        self.assertEqual(result['token'], "some_token_value")
