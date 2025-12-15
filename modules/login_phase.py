# modules/login_phase.py
import socket
import struct
import asyncio
import logging
from modules.artemis_login import ArtemisLogin
from modules.protocol.pppp import PPPPProtocol

logger = logging.getLogger(__name__)

class LoginPhase:
    def __init__(self, camera_ip: str, artemis_login: ArtemisLogin, pppp: PPPPProtocol):
        self.camera_ip = camera_ip
        self.artemis_login = artemis_login
        self.pppp = pppp
        self.session_id = None

    async def execute(self) -> dict:
        logger.info("[LOGIN] Starting authentication...")

        if not await self.send_login_packet():
            return {"success": False, "error": "Failed to send login packet"}

        logger.info("[LOGIN] Authentication successful!")
        return {
            "success": True,
            "session_id": self.session_id or 1
        }

    async def send_login_packet(self) -> bool:
        logger.debug("[LOGIN] Building login packet...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 0))
        sock.setblocking(False)

        try:
            artemis_payload = self.artemis_login.build()
            packet = self.pppp.wrap_login(artemis_payload)

            logger.debug(f"[LOGIN] Sending login packet (Full Hex): {packet.hex()}")
            sock.sendto(packet, (self.camera_ip, 40611))

            loop = asyncio.get_running_loop()
            # Note: sock_recv returns bytes, not (bytes, addr)
            # sock_recvfrom returns (bytes, addr) but is new in 3.11.
            # We are using python 3.12 so sock_recvfrom is available.
            # But the previous code used sock_recv which returns only bytes, yet tried to unpack 2 values.
            # That caused "ValueError: too many values to unpack".

            # Using sock_recvfrom for safety if available, or just sock_recv and ignore addr if we don't need it.
            # We don't strictly need addr since we know who we sent it to (UDP is connectionless but we only care about reply from camera).

            if hasattr(loop, 'sock_recvfrom'):
                response, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 4096),
                    timeout=5.0
                )
            else:
                # Fallback for older python, though we are on 3.12
                response = await asyncio.wait_for(
                    loop.sock_recv(sock, 4096),
                    timeout=5.0
                )
                addr = None

            logger.debug(f"[LOGIN] Response received: {response[:20].hex()}...")

            if await self.validate_login_response(response):
                return True

            logger.error("[LOGIN] Response validation failed")
            return False

        except asyncio.TimeoutError:
            logger.error("[LOGIN] Timeout waiting for response (5s)")
            return False
        except Exception as e:
            logger.error(f"[LOGIN] Error: {e}")
            return False
        finally:
            sock.close()

    async def validate_login_response(self, response: bytes) -> bool:
        # Validierung: Magic F1, CmdType D1 oder D0
        if len(response) < 4:
            return False

        if response[0] == 0xF1 and response[1] in [0xD0, 0xD1]:
            logger.info("[LOGIN] Response validated successfully")
            # Extract session id? Maybe.
            return True

        logger.error(f"[LOGIN] Invalid response format: {response[:4].hex()}")
        return False

if __name__ == "__main__":
    async def test():
        token = '{"ret": 0, "ssid": "KJK_E0FF"}'
        artemis_login = ArtemisLogin(token, 0x0048, b'DEVICE_ID_20BYTES')
        pppp = PPPPProtocol()

        # Need mock responding to Login on port 40611
        login = LoginPhase("127.0.0.1", artemis_login, pppp)
        result = await login.execute()
        print(f"Login result: {result}")

    asyncio.run(test())
