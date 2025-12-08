"""Multi-threaded Connection Manager inspired by libArLink.so architecture.

The original Android TrailCam Go app uses the PPCS (P2P Push Proxy Connection
Service) library which implements three parallel connection threads:
  - P2P Direct Connection (UDP)
  - LAN Direct Connection (UDP) 
  - TCP Relay Connection (through relay server)

This module replicates that architecture pattern in Python for more robust
and faster connection establishment with automatic failover.

Key design principles from libArLink.so:
  1. Per-thread socket management (no global port caching)
  2. Automatic port assignment by OS (bind port=0)
  3. Parallel threads that race to connect
  4. First successful thread wins, others are terminated
  5. Automatic cleanup and port reclamation on failure
"""

import socket
import threading
import time
from typing import Optional, Dict, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import logging


class ConnectionMode(Enum):
    """Connection modes matching libArLink.so terminology."""
    P2P = "p2p"          # Direct peer-to-peer UDP
    LAN = "lan"          # LAN direct UDP
    RELAY = "relay"      # TCP relay through server


class ConnectionThreadState(Enum):
    """States for individual connection threads."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ThreadSocketInfo:
    """Per-thread socket information (inspired by cs2p2pSessionInfo from libArLink.so)."""
    thread_id: int
    thread_name: str
    mode: ConnectionMode
    socket_fd: Optional[socket.socket] = None
    local_port: Optional[int] = None
    destination_port: Optional[int] = None
    retry_count: int = 0
    max_retries: int = 3
    state: ConnectionThreadState = ConnectionThreadState.PENDING
    error: Optional[str] = None
    timestamp_started: Optional[float] = None
    timestamp_ended: Optional[float] = None

    @property
    def elapsed_time(self) -> Optional[float]:
        """Calculate elapsed time for this thread."""
        if self.timestamp_started is None:
            return None
        end = self.timestamp_ended or time.time()
        return end - self.timestamp_started

    def __str__(self) -> str:
        return (
            f"{self.thread_name} ({self.mode.value}): "
            f"state={self.state.value}, port={self.local_port}, "
            f"elapsed={self.elapsed_time:.2f}s"
        )


class ParallelConnectionManager:
    """Manager for parallel connection attempts inspired by libArLink.so.
    
    Attributes:
        logger: Logger instance for debug output
        camera_ip: Target camera IP address
        destination_ports: List of ports to try (in order)
        relay_server: Optional relay server info
        max_connection_time: Maximum total time to attempt connections
    """

    def __init__(
        self,
        camera_ip: str,
        destination_ports: Tuple[int, ...] = (40611, 32100, 32108, 10000, 80, 57743),
        max_connection_time: float = 30.0,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the parallel connection manager.
        
        Args:
            camera_ip: Target camera IP address
            destination_ports: Tuple of ports to try (first is primary)
            max_connection_time: Max seconds to spend on connection attempts
            logger: Optional logger instance
        """
        self.camera_ip = camera_ip
        self.destination_ports = destination_ports
        self.max_connection_time = max_connection_time
        self.logger = logger or logging.getLogger(__name__)

        # Thread management
        self._threads: Dict[str, threading.Thread] = {}
        self._thread_infos: Dict[str, ThreadSocketInfo] = {}
        self._lock = threading.Lock()
        self._winning_thread_name: Optional[str] = None
        self._start_time: Optional[float] = None

    def connect_parallel(
        self,
        enable_p2p: bool = True,
        enable_lan: bool = True,
        enable_relay: bool = False,
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Attempt connection using all enabled threads in parallel.
        
        This replicates the libArLink.so behavior where P2P, LAN, and Relay
        threads all attempt connection simultaneously. The first successful
        thread wins, and the others are terminated.
        
        Args:
            enable_p2p: Start P2P direct connection thread
            enable_lan: Start LAN direct connection thread  
            enable_relay: Start relay connection thread (requires relay server)
            
        Returns:
            Tuple of (success: bool, connection_info: dict | None)
            where connection_info contains:
              - mode: ConnectionMode that succeeded
              - port: Local source port used
              - elapsed_time: Total connection time
              - threads_info: Info about all threads
        """
        self._start_time = time.time()
        self.logger.info("[CONNECT] Starting parallel connection attempt...")

        threads_to_start = []

        # Create and start P2P thread
        if enable_p2p:
            t = threading.Thread(
                target=self._p2p_connect_thread,
                name="p2pConnectThread",
                daemon=True,
            )
            threads_to_start.append(t)
            self._thread_infos["p2pConnectThread"] = ThreadSocketInfo(
                thread_id=len(threads_to_start),
                thread_name="p2pConnectThread",
                mode=ConnectionMode.P2P,
            )

        # Create and start LAN thread
        if enable_lan:
            t = threading.Thread(
                target=self._lan_connect_thread,
                name="lanConnectThread",
                daemon=True,
            )
            threads_to_start.append(t)
            self._thread_infos["lanConnectThread"] = ThreadSocketInfo(
                thread_id=len(threads_to_start),
                thread_name="lanConnectThread",
                mode=ConnectionMode.LAN,
            )

        # Create and start Relay thread
        if enable_relay:
            t = threading.Thread(
                target=self._relay_connect_thread,
                name="relayConnectThread",
                daemon=True,
            )
            threads_to_start.append(t)
            self._thread_infos["relayConnectThread"] = ThreadSocketInfo(
                thread_id=len(threads_to_start),
                thread_name="relayConnectThread",
                mode=ConnectionMode.RELAY,
            )

        # Start all threads
        for thread in threads_to_start:
            thread.start()
            self.logger.debug(f"[CONNECT] Started thread: {thread.name}")

        # Wait for first success or all failures
        result = self._wait_for_connection_result(threads_to_start)

        elapsed = time.time() - self._start_time
        self.logger.info(f"[CONNECT] Parallel connection attempt completed in {elapsed:.2f}s")

        return result

    def _p2p_connect_thread(self) -> None:
        """P2P direct connection thread (peer-to-peer UDP).
        
        This matches the p2pConnectThread from libArLink.so:
          1. Creates a new socket (OS assigns ephemeral port)
          2. Tries each destination port
          3. Closes socket if all fail
          4. Does NOT cache port globally
        """
        info = self._thread_infos["p2pConnectThread"]
        info.state = ConnectionThreadState.RUNNING
        info.timestamp_started = time.time()

        self.logger.debug(
            "[P2P] Starting P2P direct connection thread"
        )

        try:
            for dest_port in self.destination_ports:
                if self._winning_thread_name is not None:
                    # Another thread won
                    self.logger.debug(
                        f"[P2P] Another thread succeeded ({self._winning_thread_name}), "
                        f"aborting P2P attempts"
                    )
                    info.state = ConnectionThreadState.CANCELLED
                    return

                # Create new socket for this attempt (key difference from buggy Python client)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(5.0)

                    # Bind to OS-assigned port (port=0)
                    sock.bind(("", 0))
                    local_port = sock.getsockname()[1]

                    info.socket_fd = sock
                    info.local_port = local_port
                    info.destination_port = dest_port

                    self.logger.debug(
                        f"[P2P] Attempt {info.retry_count + 1}: "
                        f"local_port={local_port}, dest_port={dest_port}"
                    )

                    # Try to connect to destination
                    if self._try_discovery(
                        sock, self.camera_ip, dest_port, local_port
                    ):
                        # SUCCESS!
                        with self._lock:
                            self._winning_thread_name = "p2pConnectThread"
                        info.state = ConnectionThreadState.SUCCESS
                        info.timestamp_ended = time.time()
                        self.logger.info(
                            f"[P2P] ✓ P2P connection succeeded: "
                            f"port={local_port}, dest_port={dest_port}, "
                            f"time={info.elapsed_time:.2f}s"
                        )
                        return

                    # Cleanup for next attempt
                    sock.close()
                    info.socket_fd = None
                    info.retry_count += 1

                except Exception as e:
                    info.error = str(e)
                    self.logger.debug(f"[P2P] Socket error on port {dest_port}: {e}")
                    if info.socket_fd:
                        try:
                            info.socket_fd.close()
                        except:
                            pass
                        info.socket_fd = None

        except Exception as e:
            info.error = str(e)
            self.logger.error(f"[P2P] Unexpected error in P2P thread: {e}")
        finally:
            info.state = ConnectionThreadState.FAILED
            info.timestamp_ended = time.time()
            self.logger.warning(
                f"[P2P] P2P connection failed after {info.retry_count} attempts "
                f"({info.elapsed_time:.2f}s)"
            )

    def _lan_connect_thread(self) -> None:
        """LAN direct connection thread.
        
        Identical logic to P2P but marked as LAN mode for statistics/diagnostics.
        """
        info = self._thread_infos["lanConnectThread"]
        info.state = ConnectionThreadState.RUNNING
        info.timestamp_started = time.time()

        self.logger.debug("[LAN] Starting LAN direct connection thread")

        try:
            for dest_port in self.destination_ports:
                if self._winning_thread_name is not None:
                    self.logger.debug(
                        f"[LAN] Another thread succeeded ({self._winning_thread_name}), "
                        f"aborting LAN attempts"
                    )
                    info.state = ConnectionThreadState.CANCELLED
                    return

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(5.0)
                    sock.bind(("", 0))
                    local_port = sock.getsockname()[1]

                    info.socket_fd = sock
                    info.local_port = local_port
                    info.destination_port = dest_port

                    self.logger.debug(
                        f"[LAN] Attempt {info.retry_count + 1}: "
                        f"local_port={local_port}, dest_port={dest_port}"
                    )

                    if self._try_discovery(
                        sock, self.camera_ip, dest_port, local_port
                    ):
                        with self._lock:
                            self._winning_thread_name = "lanConnectThread"
                        info.state = ConnectionThreadState.SUCCESS
                        info.timestamp_ended = time.time()
                        self.logger.info(
                            f"[LAN] ✓ LAN connection succeeded: "
                            f"port={local_port}, dest_port={dest_port}, "
                            f"time={info.elapsed_time:.2f}s"
                        )
                        return

                    sock.close()
                    info.socket_fd = None
                    info.retry_count += 1

                except Exception as e:
                    info.error = str(e)
                    self.logger.debug(f"[LAN] Socket error on port {dest_port}: {e}")
                    if info.socket_fd:
                        try:
                            info.socket_fd.close()
                        except:
                            pass
                        info.socket_fd = None

        except Exception as e:
            info.error = str(e)
            self.logger.error(f"[LAN] Unexpected error in LAN thread: {e}")
        finally:
            info.state = ConnectionThreadState.FAILED
            info.timestamp_ended = time.time()
            self.logger.warning(
                f"[LAN] LAN connection failed after {info.retry_count} attempts "
                f"({info.elapsed_time:.2f}s)"
            )

    def _relay_connect_thread(self) -> None:
        """TCP relay connection thread.
        
        Placeholder for future relay server implementation.
        Would negotiate relay port dynamically with server.
        """
        info = self._thread_infos["relayConnectThread"]
        info.state = ConnectionThreadState.RUNNING
        info.timestamp_started = time.time()

        self.logger.debug("[RELAY] Starting relay connection thread")
        self.logger.warning("[RELAY] Relay connection not yet implemented")

        info.state = ConnectionThreadState.FAILED
        info.timestamp_ended = time.time()

    def _try_discovery(
        self,
        sock: socket.socket,
        target_ip: str,
        dest_port: int,
        local_port: int,
    ) -> bool:
        """Try to discover device on specified port.
        
        Args:
            sock: UDP socket to use
            target_ip: Target IP address
            dest_port: Destination port to try
            local_port: Local source port being used
            
        Returns:
            True if discovery successful, False otherwise
        """
        # Placeholder: actual discovery protocol would go here
        # For now, just attempt to send a probe packet
        try:
            # In real implementation, this would send ARTEMIS discovery probe
            sock.sendto(b"\x00" * 8, (target_ip, dest_port))
            return True
        except Exception:
            return False

    def _wait_for_connection_result(
        self, threads: list
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Wait for first thread success or all to fail.
        
        Args:
            threads: List of threads to monitor
            
        Returns:
            Tuple of (success, connection_info)
        """
        timeout_at = time.time() + self.max_connection_time

        while time.time() < timeout_at:
            # Check if any thread succeeded
            if self._winning_thread_name:
                winning_info = self._thread_infos[self._winning_thread_name]
                return (
                    True,
                    {
                        "mode": winning_info.mode,
                        "port": winning_info.local_port,
                        "destination_port": winning_info.destination_port,
                        "elapsed_time": winning_info.elapsed_time,
                        "winning_thread": self._winning_thread_name,
                        "threads_info": {
                            name: {
                                "mode": info.mode.value,
                                "state": info.state.value,
                                "port": info.local_port,
                                "retries": info.retry_count,
                                "elapsed": info.elapsed_time,
                                "error": info.error,
                            }
                            for name, info in self._thread_infos.items()
                        },
                    },
                )

            # Check if all threads finished
            all_finished = all(
                info.state in (ConnectionThreadState.FAILED, ConnectionThreadState.CANCELLED)
                for info in self._thread_infos.values()
            )
            if all_finished:
                return (
                    False,
                    {
                        "elapsed_time": time.time() - self._start_time,
                        "threads_info": {
                            name: {
                                "mode": info.mode.value,
                                "state": info.state.value,
                                "port": info.local_port,
                                "retries": info.retry_count,
                                "elapsed": info.elapsed_time,
                                "error": info.error,
                            }
                            for name, info in self._thread_infos.items()
                        },
                    },
                )

            time.sleep(0.1)

        # Timeout
        self.logger.error(
            f"[CONNECT] Connection timeout after {self.max_connection_time}s"
        )
        return (False, None)
