#!/usr/bin/env python3
"""Unit tests for login token extraction using known MITM captures."""

import base64
import json
import struct
import unittest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


PHASE2_KEY = b"a01bc23ed45fF56A"
ARTEMIS_NULL = b"ARTEMIS\x00"


class TestLoginDecryption(unittest.TestCase):
    """Test token extraction from real MITM captures."""

    def test_decrypt_login_response_from_mitm(self):
        """Test decrypting the login response from ble_udp_2.log.
        
        This is the actual MsgType=3 AppSeq=1 response captured from a successful
        login that should contain a token.
        
        From ble_udp_2.log lines 388-397:
        RUDP header: f1 d0 00 99 d1 00 00 01
        ARTEMIS header: ARTEMIS\x00 03 00 00 00 01 00 00 00 81 00 00 00
        Base64 payload: 7sQ3+pH/khrx+xvDdflBd8USOk3YZmkaUTUY/OERhIxBO2SC8eXiQxFKGfMMNlzLwMIwCU+d+Z3AbMRgF74MToYblQV2XNg8ZRDuzBfkf2M=
        """
        # The full UDP packet from the capture
        udp_packet = bytes.fromhex(
            "f1d00099d1000001415254454d49530003000000010000008100000037735133"
            "2b70482f6b6872782b787644646665624864385553"
            "4f6b33595a6d6b615554555"
            "92f4f455268497842"
            "4f3253433865586951784"
            "64b47664d4d4e6c7a4c774d49774355"
            "2b642b5a3341624d5267463734"
            "4d546f59626c5156325"
            "84e67385a5244757a42666b66324d3d"
            "00000000000000000000000000000000000000000000000000"
        )

        # Extract ARTEMIS section (skip RUDP 8-byte header)
        artemis_start = 8
        artemis_data = udp_packet[artemis_start:]

        # Validate ARTEMIS header
        self.assertTrue(artemis_data.startswith(ARTEMIS_NULL))

        # Parse ARTEMIS header (little-endian)
        msg_type, app_seq, payload_len = struct.unpack("<III", artemis_data[8:20])
        self.assertEqual(msg_type, 3, "Should be MsgType=3 (response)")
        self.assertEqual(app_seq, 1, "Should be AppSeq=1 (login)")

        # Extract Base64 payload
        payload_start = 20
        payload_end = payload_start + payload_len
        b64_data = artemis_data[payload_start:payload_end]
        
        # Remove null terminator
        b64_data = b64_data.split(b"\x00")[0]
        
        # Pad if needed
        if len(b64_data) % 4 != 0:
            b64_data += b"=" * (4 - (len(b64_data) % 4))

        # Decode Base64
        encrypted = base64.b64decode(b64_data)
        
        # Decrypt with AES-ECB
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)
        
        # Try standard unpad
        try:
            unpadded = unpad(decrypted, AES.block_size)
            json_str = unpadded.decode("utf-8")
        except Exception:
            # Try manual unpad (find last '}')
            s = decrypted.decode("utf-8", errors="ignore")
            end_idx = s.rfind("}")
            self.assertNotEqual(end_idx, -1, "Should find JSON end marker")
            json_str = s[:end_idx + 1]

        # Parse JSON
        data = json.loads(json_str)
        
        # Validate login response structure
        self.assertIsInstance(data, dict)
        self.assertIn("cmdId", data)
        self.assertEqual(data["cmdId"], 0, "Should be login response (cmdId=0)")
        
        # Check for token
        self.assertIn("token", data, "Login response should contain token")
        self.assertIsInstance(data["token"], str)
        self.assertGreater(len(data["token"]), 0, "Token should not be empty")
        
        print(f"✅ Successfully extracted token: {data['token'][:20]}... (len={len(data['token'])})")
        print(f"Full response: {json.dumps(data, indent=2)}")

    def test_encrypt_login_request(self):
        """Test that we can create a valid encrypted login request."""
        import time
        
        login_json = {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "needAudio": 0,
            "utcTime": int(time.time()),
            "supportHeartBeat": True
        }
        
        # Serialize to JSON
        json_str = json.dumps(login_json, separators=(",", ":"))
        json_bytes = json_str.encode("utf-8")
        
        # Pad and encrypt
        padded = pad(json_bytes, AES.block_size)
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(padded)
        
        # Encode to Base64
        b64 = base64.b64encode(encrypted)
        
        # Verify we can decrypt it back
        decrypted = cipher.decrypt(base64.b64decode(b64))
        unpadded = unpad(decrypted, AES.block_size)
        recovered = json.loads(unpadded.decode("utf-8"))
        
        self.assertEqual(recovered, login_json)
        print(f"✅ Created valid encrypted login request (b64 len={len(b64)})")


if __name__ == "__main__":
    unittest.main(verbosity=2)
