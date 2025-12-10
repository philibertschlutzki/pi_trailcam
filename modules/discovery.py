# modules/discovery.py
import socket
import struct
import asyncio
import logging
from modules.protocol.pppp import PPPPProtocol

logger = logging.getLogger(__name__)

class DiscoveryPhase:
    def __init__(self, camera_ip: str, artemis_seq: int, pppp: PPPPProtocol):
        self.camera_ip = camera_ip
        self.artemis_seq = artemis_seq
        self.pppp = pppp
        self.device_id = None
        self.device_info = None

    async def execute(self) -> dict:
        try:
            if not await self.phase_1_lan_search():
                return {"success": False, "error": "Phase 1 failed"}

            if not await self.phase_2_port_punching():
                return {"success": False, "error": "Phase 2 failed"}

            if not await self.phase_3_p2p_ready():
                return {"success": False, "error": "Phase 3 failed"}

            return {
                "success": True,
                "device_id": self.device_id,
                "device_info": self.device_info
            }
        except Exception as e:
            logger.error(f"Discovery execution failed: {e}")
            return {"success": False, "error": str(e)}

    async def phase_1_lan_search(self) -> bool:
        logger.info("[DISCOVERY] Phase 1: LAN search starting...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 0))
        sock.setblocking(False) # For asyncio

        try:
            packet = self.pppp.wrap_discovery(self.artemis_seq)
            logger.debug(f"Sending discovery packet: {packet.hex()}")

            sock.sendto(packet, (self.camera_ip, 32108))

            # Async receive with timeout
            loop = asyncio.get_running_loop()
            response_data = await asyncio.wait_for(
                loop.sock_recv(sock, 1024),
                timeout=5.0
            )

            logger.debug(f"Response received: {response_data[:20].hex()}...")

            # Validate response (Magic F1, CmdType DD or D1)
            if len(response_data) > 4 and response_data[0] == 0xF1:
                 # Check CMD Type. DD or D1?
                 # Prompt says DD or D1.
                 if response_data[1] in [0xDD, 0xD1]:
                    # Extract Device-Info
                    # Offset 4 (Outer Header) + Inner Header (5)? = 9?
                    # Plan says "20 bytes nach Offset 4". But response usually has Inner Header too?
                    # Plan says: "Extract Device-Info (52 bytes nach Position 4)"
                    # Let's assume after Outer Header (4 bytes).
                    if len(response_data) >= 56:
                        self.device_info = response_data[4:56]
                        self.device_id = self.device_info[:20]
                    else:
                        self.device_info = response_data[4:]
                        self.device_id = self.device_info[:20] # Best effort

                    logger.info("[DISCOVERY] Phase 1: Success!")
                    return True

            logger.error(f"Invalid response format: {response_data[:4].hex()}")
            return False

        except asyncio.TimeoutError:
            logger.warning("[DISCOVERY] Phase 1: Timeout after 5s")
            return False
        except Exception as e:
            logger.error(f"[DISCOVERY] Phase 1 error: {e}")
            return False
        finally:
            sock.close()

    async def phase_2_port_punching(self) -> bool:
        logger.info("[DISCOVERY] Phase 2: Port punching starting...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 0))
        sock.setblocking(False)

        try:
            # CmdType 0x41
            # Format: F1 41 00 14 00 + DeviceID (20)
            # 0x0014 = 20 decimal. 00 is Inner Subcommand? Or just padding?
            # Prompt says: struct.pack('>BBHB', 0xF1, 0x41, 0x0014, 0x00) + device_id
            # This looks like Outer Header with no Inner Header, or specialized header.
            # >BBHB: F1(1), 41(1), 0014(2), 00(1). Total 5 bytes.
            # Plus 20 bytes payload = 25 bytes?
            # Wait, Length field in Outer header should encompass payload?
            # 0x0014 is length field? 20 bytes?
            # If length is 20, then payload is 20 bytes.
            # But the pack string adds a 'B' (0x00) at end. 5 bytes.
            # Let's trust the prompt: `struct.pack('>BBHB', 0xF1, 0x41, 0x0014, 0x00) + device_id`
            # Wait, 0x0014 is 20. If that's length, then device_id matches.
            # So F1 41 00 14 00 [20 bytes].

            header = struct.pack('>BBHB', 0xF1, 0x41, 0x0014, 0x00)
            packet = header + self.device_id

            sock.sendto(packet, (self.camera_ip, 40611))

            loop = asyncio.get_running_loop()
            response_data = await asyncio.wait_for(
                loop.sock_recv(sock, 1024),
                timeout=5.0
            )

            if len(response_data) > 1 and response_data[0] == 0xF1 and response_data[1] == 0x41:
                logger.info("[DISCOVERY] Phase 2: Port punching successful")
                return True

            logger.error("Phase 2: Invalid response")
            return False

        except asyncio.TimeoutError:
            logger.warning("[DISCOVERY] Phase 2: Timeout")
            return False
        except Exception as e:
            logger.error(f"[DISCOVERY] Phase 2 error: {e}")
            return False
        finally:
            sock.close()

    async def phase_3_p2p_ready(self) -> bool:
        logger.info("[DISCOVERY] Phase 3: P2P ready starting...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 0))
        sock.setblocking(False)

        try:
            # CmdType 0x42
            header = struct.pack('>BBHB', 0xF1, 0x42, 0x0014, 0x00)
            packet = header + self.device_id

            sock.sendto(packet, (self.camera_ip, 40611))

            loop = asyncio.get_running_loop()
            response_data = await asyncio.wait_for(
                loop.sock_recv(sock, 1024),
                timeout=5.0
            )

            if len(response_data) > 1 and response_data[0] == 0xF1 and response_data[1] == 0x42:
                logger.info("[DISCOVERY] Phase 3: P2P ready confirmed")
                return True

            logger.error("Phase 3: Invalid response")
            return False

        except asyncio.TimeoutError:
            logger.warning("[DISCOVERY] Phase 3: Timeout")
            return False
        except Exception as e:
            logger.error(f"[DISCOVERY] Phase 3 error: {e}")
            return False
        finally:
            sock.close()

if __name__ == "__main__":
    # Integration test with Mock (if running)
    async def test():
        logging.basicConfig(level=logging.DEBUG)
        pppp = PPPPProtocol()
        # Ensure mock is running on localhost:32108 and 40611
        discovery = DiscoveryPhase("127.0.0.1", 0x0048, pppp)
        result = await discovery.execute()
        print(f"Discovery result: {result}")

    asyncio.run(test())
