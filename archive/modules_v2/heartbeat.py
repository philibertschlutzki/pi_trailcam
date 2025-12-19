# modules/heartbeat.py
import socket
import asyncio
import json
import time
import logging
from modules.protocol.pppp import PPPPProtocol

logger = logging.getLogger(__name__)

class HeartbeatManager:
    def __init__(self, camera_ip: str, pppp: PPPPProtocol, socket_obj: socket.socket = None):
        self.camera_ip = camera_ip
        self.pppp = pppp
        self.socket = socket_obj or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = False
        self.missed_heartbeats = 0
        self.last_heartbeat_time = time.time()
        self.interval_sec = 3.0

    async def start(self, interval_sec: float = 3.0):
        """
        Starte Heartbeat-Loop

        Sendet alle 3.0 Sekunden ein Heartbeat-Paket
        """
        logger.info("[HB] Heartbeat started")
        self.running = True
        self.interval_sec = interval_sec
        self.last_heartbeat_time = time.time()

        while self.running:
            now = time.time()
            elapsed = now - self.last_heartbeat_time

            if elapsed >= self.interval_sec:
                try:
                    # Sende Heartbeat
                    json_payload = json.dumps({"cmdId": 525}).encode('utf-8')
                    packet = self.pppp.wrap_heartbeat(json_payload)

                    self.socket.sendto(packet, (self.camera_ip, 40611))

                    logger.debug(f"[HB] Heartbeat sent (seq: {self.pppp.pppp_sequence})")

                    self.last_heartbeat_time = now
                    self.missed_heartbeats = 0

                except Exception as e:
                    logger.warning(f"[HB] Heartbeat failed: {e}")
                    self.missed_heartbeats += 1

                    if self.missed_heartbeats >= 3:
                        logger.error(f"[HB] Reconnect signal: {self.missed_heartbeats} consecutive failures")
                        # Signal an Hauptprogramm: Reconnect erforderlich
                        self.running = False
                        break

            # CPU-schonend: hochfrequent prüfen, aber nicht vollständig blocken
            await asyncio.sleep(0.1)

    async def stop(self):
        """Stoppe Heartbeat-Loop und schließe Socket"""
        logger.info("[HB] Heartbeat stopped")
        self.running = False
        # Do not close socket if it was passed in externally, unless we own it?
        # The prompt says: "if self.socket: self.socket.close()"
        # But if we reuse socket for commands, closing it here might be bad.
        # Assuming ownership for now as per prompt.
        try:
             self.socket.close()
        except:
             pass
