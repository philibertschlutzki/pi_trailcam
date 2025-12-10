# modules/command_engine.py
import socket
import json
import asyncio
import logging
from typing import Dict, Optional, Any
from modules.protocol.pppp import PPPPProtocol

logger = logging.getLogger(__name__)

class CommandEngine:
    def __init__(self, camera_ip: str, pppp: PPPPProtocol, socket_obj: socket.socket):
        self.camera_ip = camera_ip
        self.pppp = pppp
        self.socket = socket_obj

    async def send_command(self, cmd_id: int, payload: Dict = None, timeout_sec: float = 5.0) -> Dict[str, Any]:
        """
        Sende Command zur Kamera

        Args:
            cmd_id: Command ID (z.B. 512 für device info)
            payload: Zusätzliche Felder für JSON
            timeout_sec: Response-Timeout

        Returns:
            Command-Response oder Error-Dict
        """
        full_payload = {"cmdId": cmd_id}
        if payload:
            full_payload.update(payload)

        json_bytes = json.dumps(full_payload).encode('utf-8')
        packet = self.pppp.wrap_command(json_bytes)

        logger.debug(f"[CMD] Sending command {cmd_id}: {full_payload}")

        try:
            self.socket.sendto(packet, (self.camera_ip, 40611))

            loop = asyncio.get_running_loop()
            if hasattr(loop, 'sock_recvfrom'):
                response_data, _ = await asyncio.wait_for(
                    loop.sock_recvfrom(self.socket, 4096),
                    timeout=timeout_sec
                )
            else:
                response_data = await asyncio.wait_for(
                    loop.sock_recv(self.socket, 4096),
                    timeout=timeout_sec
                )

            # Parse PPPP + JSON Response
            response_json = self._parse_response(response_data)

            logger.debug(f"[CMD] Response: {response_json}")

            return response_json

        except asyncio.TimeoutError:
            logger.error(f"[CMD] Command {cmd_id} timeout")
            return {"error": "timeout", "cmdId": cmd_id}
        except Exception as e:
            logger.error(f"[CMD] Command {cmd_id} error: {e}")
            return {"error": str(e), "cmdId": cmd_id}

    def _parse_response(self, data: bytes) -> dict:
        """
        Parse PPPP-wrapped JSON Response

        PPPP-Format: [Outer (4) + Inner (4/5) + JSON Payload]
        """
        try:
            # Skip PPPP headers
            # Outer header is 4 bytes.
            # Inner header is 5 bytes.
            # Total 9 bytes usually.
            # But let's look for '{' to be safe.

            # Try finding start of JSON
            try:
                json_str = data.decode('utf-8', errors='ignore')
            except:
                return {"error": "decode_error"}

            json_start = json_str.find('{')
            if json_start != -1:
                # Find matching brace or just take rest?
                # Taking rest is safer for now if packet is clean.
                # But packets might have padding?
                # Let's try parsing from start index.
                json_candidate = json_str[json_start:]
                # Trim potential null bytes at end
                json_candidate = json_candidate.rstrip('\x00')
                try:
                     return json.loads(json_candidate)
                except json.JSONDecodeError:
                     # Try to find last '}'
                     json_end = json_candidate.rfind('}')
                     if json_end != -1:
                         return json.loads(json_candidate[:json_end+1])
                     raise

            return {"error": "invalid_json", "raw": data[:20].hex()}
        except Exception as e:
            logger.error(f"Parse response error: {e}")
            return {"error": "parse_error"}

    async def get_device_info(self) -> dict:
        """Rufe Device-Info ab (cmdId 512)"""
        return await self.send_command(512, {})

if __name__ == "__main__":
    import asyncio

    async def test():
        # Requires setup
        pass

    # asyncio.run(test())
