"""Heartbeat manager for maintaining active UDP session.

The heartbeat mechanism was observed in the 2025-12-08 application log,
where cmdId:525 packets are sent every ~3 seconds to keep the UDP
connection alive and prevent NAT/firewall timeouts.

Log evidence:
[2025-12-08 18:34:05.526] sendCommand:{"cmdId":525}, seq:65537
[2025-12-08 18:34:08.534] sendCommand:{"cmdId":525}, seq:65538
[2025-12-08 18:34:11.544] sendCommand:{"cmdId":525}, seq:65539
Interval: ~3 seconds
"""

import asyncio
import logging
import time
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..camera_client import CameraClient

from .command_ids import CMD_HEARTBEAT, HEARTBEAT_INTERVAL_SEC


class HeartbeatManager:
    """Manages periodic heartbeat/keep-alive packets.
    
    This class implements the keep-alive mechanism observed in the Android app,
    where CMD_HEARTBEAT (525) packets are sent regularly to maintain the UDP
    session and prevent timeouts.
    
    Attributes:
        camera_client: CameraClient instance to send commands through
        interval_sec: Heartbeat interval in seconds (default: 3.0)
        logger: Logger instance
    """

    def __init__(
        self,
        camera_client: "CameraClient",
        interval_sec: float = HEARTBEAT_INTERVAL_SEC,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize heartbeat manager.
        
        Args:
            camera_client: CameraClient instance for sending heartbeat commands
            interval_sec: Interval between heartbeats (default: 3.0 seconds)
            logger: Optional logger instance
        """
        self.camera_client = camera_client
        self.interval_sec = interval_sec
        self.logger = logger or logging.getLogger(__name__)
        
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._last_heartbeat_time: Optional[float] = None
        self._heartbeat_count = 0
        self._failed_count = 0

    async def start(self) -> None:
        """Start the heartbeat thread.
        
        Begins sending periodic CMD_HEARTBEAT (525) packets to the camera.
        This should be called after successful login.
        
        Log output will match Android app format:
        [INFO] Start join heart beat thread
        """
        if self._running:
            self.logger.warning("[HEARTBEAT] Already running, ignoring start request")
            return

        self._running = True
        self._heartbeat_count = 0
        self._failed_count = 0
        
        self.logger.info("[HEARTBEAT] Start join heart beat thread")
        self._task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self) -> None:
        """Stop the heartbeat thread.
        
        Cancels the heartbeat task and waits for cleanup.
        
        Log output:
        [INFO] heart beat thread joined
        """
        if not self._running:
            return

        self._running = False
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        
        self.logger.info("[HEARTBEAT] heart beat thread joined")

    async def _heartbeat_loop(self) -> None:
        """Main heartbeat loop.
        
        Sends CMD_HEARTBEAT packets at regular intervals.
        Matches the Android app behavior observed in logs.
        """
        try:
            while self._running:
                try:
                    # Send heartbeat command
                    await self._send_heartbeat()
                    
                    # Wait for next interval
                    await asyncio.sleep(self.interval_sec)
                    
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self._failed_count += 1
                    self.logger.warning(
                        f"[HEARTBEAT] Heartbeat failed (count: {self._failed_count}): {e}"
                    )
                    
                    # If too many failures, consider stopping
                    if self._failed_count >= 5:
                        self.logger.error(
                            "[HEARTBEAT] Too many consecutive failures, stopping heartbeat"
                        )
                        self._running = False
                        break
                    
                    # Wait before retry
                    await asyncio.sleep(self.interval_sec)
        
        finally:
            self.logger.debug("[HEARTBEAT] Heartbeat loop ended")

    async def _send_heartbeat(self) -> None:
        """Send a single heartbeat packet.
        
        Sends CMD_HEARTBEAT (525) with minimal payload.
        Format matches log observation: {"cmdId":525}
        """
        self._heartbeat_count += 1
        current_time = time.time()
        
        # Log in Android app format (WARN level for heartbeat commands)
        self.logger.debug(
            f"[HEARTBEAT] sendCommand:{{\"cmdId\":{CMD_HEARTBEAT}}}, "
            f"seq:{65536 + self._heartbeat_count}"
        )
        
        try:
            # Send minimal heartbeat command
            # The camera_client should handle sequence numbers internally
            response = await self.camera_client.send_command(
                cmd_id=CMD_HEARTBEAT,
                payload=None,  # Minimal payload
                timeout_sec=2.0,  # Short timeout for heartbeat
            )
            
            self._last_heartbeat_time = current_time
            self._failed_count = 0  # Reset failure counter on success
            
            # Log packet size (45 bytes observed in logs)
            self.logger.debug(
                f"[HEARTBEAT] Send cmd to dev complete, len:45"
            )
            
        except Exception as e:
            self.logger.warning(f"[HEARTBEAT] Failed to send heartbeat: {e}")
            raise

    @property
    def is_running(self) -> bool:
        """Check if heartbeat is currently running."""
        return self._running

    @property
    def heartbeat_count(self) -> int:
        """Get total number of heartbeats sent."""
        return self._heartbeat_count

    @property
    def last_heartbeat_time(self) -> Optional[float]:
        """Get timestamp of last successful heartbeat."""
        return self._last_heartbeat_time

    @property
    def seconds_since_last_heartbeat(self) -> Optional[float]:
        """Get seconds elapsed since last successful heartbeat."""
        if self._last_heartbeat_time is None:
            return None
        return time.time() - self._last_heartbeat_time
