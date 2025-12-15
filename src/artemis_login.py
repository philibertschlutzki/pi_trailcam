import socket
import struct
import time
import logging
import asyncio
import json
from typing import Optional, Tuple, Dict

# Configure logger
logger = logging.getLogger("ArtemisLogin")
# logging basic config should be handled by main app, but for standalone run:
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class ArtemisLoginHandler:
    """
    Handles the 4-phase login sequence for TrailCam Go (KJK230).
    Phase 1: Initialization Wake-up
    Phase 2: Discovery
    Phase 3: Artemis Login
    Phase 4: Post-Login Setup (Heartbeat)
    """

    def __init__(self, target_ip: str, target_port: int = 40611, ble_token: str = "admin", ble_sequence: int = 1):
        self.target_ip = target_ip
        self.target_port = target_port
        self.ble_token = ble_token
        self.ble_sequence = ble_sequence

        self.sock: Optional[socket.socket] = None
        self.device_uid: Optional[str] = None
        self.is_connected = False

        # State tracking
        self.pppp_seq = 1

    def _create_socket(self):
        if self.sock:
            self.sock.close()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('0.0.0.0', 0))
        self.sock.setblocking(False)
        logger.debug("Socket created and bound to 0.0.0.0:0")

    def _close_socket(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    async def phase1_init(self) -> bool:
        """
        PHASE 1: INITIALIZATION WAKE-UP
        Packet-Format (UDP-LAN): F1 E1 00 04 E1 00 00 01
        """
        logger.info("════════ [PHASE 1] INITIALIZATION WAKE-UP ════════")
        self._create_socket()

        # Construct specific packet: F1 E1 00 04 (Outer) + E1 00 00 01 (Inner)
        # Outer: Magic F1, Type E1, Length 4
        # Inner: Type E1, Sub 00, Seq 1

        packet = struct.pack('>BBH', 0xF1, 0xE1, 0x0004)
        packet += struct.pack('>BBH', 0xE1, 0x00, 0x0001)

        logger.info(f"[PHASE 1] [TX] {packet.hex().upper()}")
        self.sock.sendto(packet, (self.target_ip, self.target_port))

        logger.info("Wake-up burst sent. Waiting 0.5s...")
        await asyncio.sleep(0.5)
        return True

    async def phase2_discover(self) -> bool:
        """
        PHASE 2: DISCOVERY
        Send LAN Search (F1 30...) and wait for response (F1 41...).
        """
        logger.info("════════ [PHASE 2] DISCOVERY ════════")

        if not self.sock:
             self._create_socket()

        # Send LAN Search (F1 30 00 00)
        packet = struct.pack('>BBH', 0xF1, 0x30, 0x0000)

        logger.info(f"[PHASE 2] [TX] {packet.hex().upper()}")
        self.sock.sendto(packet, ('255.255.255.255', 32108))
        self.sock.sendto(packet, (self.target_ip, 32108))

        loop = asyncio.get_running_loop()
        try:
            # Wait for response
            data = await asyncio.wait_for(loop.sock_recv(self.sock, 1024), timeout=5.0)
            logger.info(f"[PHASE 2] [RX] {data.hex().upper()}")

            # Expected: F1 41 ...
            if len(data) > 4 and data[0] == 0xF1 and data[1] == 0x41:
                # Payload: f141 0014 [20 bytes UID] ...
                # Length 0x0014 = 20.

                payload = data[4:]
                if len(payload) >= 20:
                    try:
                         # Extract Device UID
                         uid_bytes = payload[:20]
                         # Decode and strip nulls
                         self.device_uid = uid_bytes.decode('utf-8', errors='ignore').rstrip('\x00')
                         logger.info(f"Device UID found: {self.device_uid}")

                         return True
                    except Exception as e:
                        logger.error(f"Failed to decode UID: {e}")

            logger.warning("Invalid discovery response format")
            return False

        except asyncio.TimeoutError:
            logger.error("Discovery timed out")
            return False

    async def phase3_login(self) -> bool:
        """
        PHASE 3: ARTEMIS LOGIN
        """
        logger.info("════════ [PHASE 3] ARTEMIS LOGIN ════════")
        if not self.device_uid:
            logger.error("Cannot login: Missing Device UID (Phase 2 failed?)")
            return False

        if not self.sock:
             self._create_socket()

        # 1. Prepare Artemis Payload
        # Magic: ARTEMIS\0
        magic = b'ARTEMIS\x00'
        # Version: 0x02000000 (LE) -> 02 00 00 00
        version = b'\x02\x00\x00\x00'

        # Seq Mystery: 01 00 00 00 (0x00000001 LE).
        seq_mystery = struct.pack('<I', self.ble_sequence)

        # Token: "admin"
        token_str = self.ble_token
        token_bytes = token_str.encode('ascii')
        token_len = struct.pack('<I', len(token_bytes))

        artemis_payload = magic + version + seq_mystery + token_len + token_bytes

        # 2. Wrap in PPPP (F1 D0...)
        # Inner Header: D1 03 00 02 (Type D1, Sub 03, Seq 2)
        inner_header = struct.pack('>BBH', 0xD1, 0x03, 0x0002)

        # Update sequence tracking: Login uses 2. Next should be 3.
        self.pppp_seq = 2

        # Outer Header: F1 D0 [Length]
        total_len = len(inner_header) + len(artemis_payload)
        outer_header = struct.pack('>BBH', 0xF1, 0xD0, total_len)

        packet = outer_header + inner_header + artemis_payload

        logger.info(f"[PHASE 3] [TX] {packet.hex().upper()}")
        self.sock.sendto(packet, (self.target_ip, self.target_port))

        # 3. Wait for Response
        try:
            loop = asyncio.get_running_loop()
            data = await asyncio.wait_for(loop.sock_recv(self.sock, 4096), timeout=3.0)

            logger.info(f"[PHASE 3] [RX] {data.hex().upper()}")

            # Validate F1 D0 ...
            if len(data) > 8 and data[0] == 0xF1 and data[1] == 0xD0:
                # Offset 8 is payload start
                payload = data[8:]

                # Try to decode
                try:
                    # Often null terminated or contains JSON
                    decoded = payload.decode('utf-8', errors='ignore')
                    logger.info(f"Decoded Payload: {decoded}")

                    # Check for success
                    # "errorCode": 0
                    if '"errorCode": 0' in decoded or '"errorCode":0' in decoded:
                        logger.info("Login Successful (errorCode=0 detected)")
                        return True

                except Exception:
                    logger.warning("Could not decode login payload")

            # If we got here, maybe we missed the check
            logger.warning("Login response validation failed (errorCode=0 not found)")
            return False

        except asyncio.TimeoutError:
            logger.error("Login timed out - No response")
            return False

    async def phase4_heartbeat(self):
        """
        PHASE 4: POST-LOGIN SETUP
        Send heartbeat every 3.0 seconds.
        """
        logger.info("════════ [PHASE 4] HEARTBEAT MANAGER ════════")
        # Ensure socket exists
        if not self.sock:
             self._create_socket()

        try:
            while True:
                # {"cmdId": 525}
                payload_str = json.dumps({"cmdId": 525})
                payload_bytes = payload_str.encode('utf-8')

                # PPPP Sequence: Login used 2. Next is 3.
                self.pppp_seq = (self.pppp_seq + 1) % 65536
                if self.pppp_seq == 0: self.pppp_seq = 1

                # Format: F1 D1 [Len] [D1 04 Seq] [Payload]
                inner = struct.pack('>BBH', 0xD1, 0x04, self.pppp_seq)
                outer = struct.pack('>BBH', 0xF1, 0xD1, len(inner) + len(payload_bytes))

                packet = outer + inner + payload_bytes

                self.sock.sendto(packet, (self.target_ip, self.target_port))
                logger.info(f"[HEARTBEAT] Sent cmdId=525, PPPP Seq={self.pppp_seq}")

                await asyncio.sleep(3.0)

        except asyncio.CancelledError:
            logger.info("Heartbeat stopped")
        except Exception as e:
            logger.error(f"Heartbeat error: {e}")

    async def execute(self):
        """Run the full sequence"""
        if await self.phase1_init():
             if await self.phase2_discover():
                 if await self.phase3_login():
                     # Start heartbeat and run forever (or until cancelled)
                     await self.phase4_heartbeat()
                 else:
                     logger.error("Phase 3 Login Failed")
             else:
                 logger.error("Phase 2 Discovery Failed")
        else:
            logger.error("Phase 1 Init Failed")

        self._close_socket()

if __name__ == "__main__":
    # Example usage
    handler = ArtemisLoginHandler(target_ip="192.168.43.1")
    try:
        asyncio.run(handler.execute())
    except KeyboardInterrupt:
        pass
