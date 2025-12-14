# modules/artemis_login.py
import struct
import json
import logging
from typing import Union

logger = logging.getLogger(__name__)

class ArtemisLogin:
    MAGIC = b'ARTEMIS\x00'
    VERSION = 0x02000000

    def __init__(self, token: str, sequence: int, device_id: bytes):
        self.token = token
        self.sequence = sequence
        self.device_id = device_id

        # Validierung
        try:
            json.loads(token)
        except json.JSONDecodeError:
            raise ValueError(f"Invalid JSON token: {token[:50]}")

        if sequence > 0xFFFFFFFF:
            raise ValueError(f"Sequence too large: {sequence}")

    def build(self) -> bytes:
        """
        Erstellt Artemis Login Payload

        Returns:
            bytes: Magic + Version + Sequence + Token Length + Token
        """
        logger.debug("[ARTEMIS] Building login payload...")

        payload = self.MAGIC
        payload += struct.pack('<I', self.VERSION)
        payload += struct.pack('<I', self.sequence)

        token_bytes = self.token.encode('utf-8')
        payload += struct.pack('<I', len(token_bytes))
        payload += token_bytes

        logger.info(f"[ARTEMIS] Login payload ready: {len(payload)} bytes")
        return payload

if __name__ == "__main__":
    token = '{"ret": 0, "ssid": "KJK_E0FF", "bssid": "...", "pwd": "..."}'
    login = ArtemisLogin(token, 0x0048, b'DEVICE_ID_20BYTES')
    payload = login.build()
    print(f"Artemis Login Payload: {payload.hex()}")
