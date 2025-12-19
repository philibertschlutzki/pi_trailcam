# modules/connection_manager.py
from enum import Enum
import asyncio
import logging
import socket
from modules.discovery import DiscoveryPhase
from modules.login_phase import LoginPhase
from modules.heartbeat import HeartbeatManager
from modules.command_engine import CommandEngine
from modules.protocol.pppp import PPPPProtocol
from modules.artemis_login import ArtemisLogin

logger = logging.getLogger(__name__)

class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    DISCOVERING = "discovering"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"
    FAILED = "failed"

class ConnectionManager:
    def __init__(self, camera_ip: str, token: str, artemis_seq: int):
        self.camera_ip = camera_ip
        self.token = token
        self.artemis_seq = artemis_seq
        self.pppp = PPPPProtocol()
        self.state = ConnectionState.DISCONNECTED
        self.socket = None
        self.heartbeat = None
        self.command_engine = None
        self.retry_count = 0
        self.max_retries = 5
        self.reconnect_task = None
    
    async def connect(self) -> bool:
        """
        Verbinde mit Kamera (alle Phasen)
        """
        self.state = ConnectionState.DISCOVERING
        
        try:
            # Discovery
            discovery = DiscoveryPhase(self.camera_ip, self.artemis_seq, self.pppp)
            discovery_result = await discovery.execute()

            if not discovery_result["success"]:
                logger.error(f"Discovery failed: {discovery_result.get('error')}")
                return False

            # Login
            self.state = ConnectionState.AUTHENTICATING

            artemis_login = ArtemisLogin(
                self.token,
                self.artemis_seq,
                discovery_result["device_id"]
            )
            
            login = LoginPhase(self.camera_ip, artemis_login, self.pppp)
            login_result = await login.execute()

            if not login_result["success"]:
                 logger.error(f"Login failed: {login_result.get('error')}")
                 return False

            # Setup Socket + Heartbeat + Commands
            # Create a persistent socket for commands and heartbeat
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setblocking(False)
            # Bind to 0 to get OS port, but we might want to reuse port from login?
            # Actually LoginPhase used a temporary socket.
            # We need to use a fresh socket or keep the one from LoginPhase?
            # LoginPhase closed its socket.
            # So we create a new one.
            self.socket.bind(('0.0.0.0', 0))

            self.heartbeat = HeartbeatManager(self.camera_ip, self.pppp, self.socket)
            self.command_engine = CommandEngine(self.camera_ip, self.pppp, self.socket)

            # Start Heartbeat
            asyncio.create_task(self.heartbeat.start())

            self.state = ConnectionState.CONNECTED
            self.retry_count = 0

            logger.info("[CONN] Connected successfully!")
            return True
            
        except Exception as e:
            logger.error(f"[CONN] Connection exception: {e}")
            self.state = ConnectionState.FAILED
            return False

    async def auto_reconnect(self):
        """
        Auto-Reconnect mit Backoff
        """
        while True:
            if self.state != ConnectionState.CONNECTED:
                wait_time = min(2 ** self.retry_count, 60)  # Exponential backoff, max 60s

                logger.warning(f"[CONN] Reconnecting in {wait_time}s...")
                await asyncio.sleep(wait_time)

                if await self.connect():
                    logger.info("[CONN] Reconnected!")
                    # Continue loop to monitor? No, loop runs forever.
                    # Wait until disconnected again?
                    # The loop checks state. If connected, it just spins?
                    # Should wait for disconnect event.
                    while self.state == ConnectionState.CONNECTED:
                        await asyncio.sleep(1)
                        if self.heartbeat and not self.heartbeat.running:
                             logger.warning("[CONN] Heartbeat stopped, triggering reconnect")
                             self.state = ConnectionState.DISCONNECTED
                else:
                    self.retry_count += 1

                    if self.retry_count > self.max_retries:
                        self.state = ConnectionState.FAILED
                        logger.error("[CONN] Max reconnect attempts exceeded")
                        break
            else:
                await asyncio.sleep(1)

    async def disconnect(self):
        """Sauberes Disconnect"""
        if self.reconnect_task:
            self.reconnect_task.cancel()

        if self.heartbeat:
            await self.heartbeat.stop()

        if self.socket:
            self.socket.close()

        self.state = ConnectionState.DISCONNECTED
        logger.info("[CONN] Disconnected")
