import socket
import time
import logging
import struct
import threading
import subprocess
import base64
import json
from enum import Enum, auto
from typing import Optional, Tuple
import config
from modules.protocol.pppp import PPPPProtocol
from modules.packet_builder import ArtemisPacketBuilder

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === ARTEMIS Login Sequence Variants ===
MYSTERY_VARIANTS = {
    'MYSTERY_09_01': bytes([0x09, 0x00, 0x01, 0x00]),
    'SMARTPHONE_DUMP': bytes([0x2b, 0x00, 0x2d, 0x00]),
    'ORIGINAL': bytes([0x02, 0x00, 0x01, 0x00]),
    'MYSTERY_2B_ONLY': bytes([0x2b, 0x00, 0x00, 0x00]),
    'MYSTERY_2D_ONLY': bytes([0x2d, 0x00, 0x00, 0x00]),
    'SEQUENCE_VARIANT': bytes([0x03, 0x00, 0x04, 0x00]),
    'BLE_DYNAMIC': None,  # Special: Use sequence_bytes directly
}

def get_wlan_ip():
    """Get IP of wlan0 when connected to camera AP (Fix #42)"""
    try:
        # Check wlan0 first
        result = subprocess.run(
            ['ip', 'addr', 'show', 'wlan0'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                parts = line.strip().split()
                if len(parts) > 1:
                    ip = parts[1].split('/')[0]
                    # Check if it looks like the camera network (usually 192.168.43.x)
                    if ip.startswith('192.168.43.') or ip.startswith('192.168.'):
                        return ip
        return None
    except Exception:
        return None

def check_firewall(logger):
    """Check if UFW is blocking UDP (Fix #42)"""
    try:
        result = subprocess.run(['sudo', 'ufw', 'status'],
                              capture_output=True, text=True, timeout=5)
        if 'inactive' in result.stdout:
            logger.info("[FIREWALL] UFW is inactive ✓")
        else:
            logger.warning(f"[FIREWALL] UFW status: {result.stdout}")
            logger.warning("[FIREWALL] Ensure UDP ports 40611, 32100, 32108, etc. are allowed!")
    except Exception as e:
        logger.warning(f"[FIREWALL] Could not check firewall: {e}")

class CameraState(Enum):
    DISCONNECTED = auto()
    INITIALIZING = auto()  # For init packet phase
    CONNECTING = auto()    # Direct login phase (no discovery)
    CONNECTED = auto()
    AUTHENTICATED = auto()
    CONNECTION_FAILED = auto()

class TimeoutContext:
    def __init__(self, socket_obj, timeout_value, logger_obj):
        self.socket = socket_obj
        self.new_timeout = timeout_value
        self.old_timeout = None
        self.logger = logger_obj
    
    def __enter__(self):
        if self.socket:
            self.old_timeout = self.socket.gettimeout()
            try:
                self.socket.settimeout(self.new_timeout)
            except Exception as e:
                self.logger.error(f"Failed to set timeout: {e}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.socket and self.old_timeout is not None:
            try:
                self.socket.settimeout(self.old_timeout)
            except Exception as e:
                self.logger.error(f"Failed to restore timeout: {e}")
        return False

class CameraClient:
    """
    FIX #48: UDP Client with direct login (no discovery phase).
    OPTIMIZED: Port Discovery and Fixed Source Port (Fix #91)
    
    Connection Flow (Android App Verified):
    Phase 1: LAN Search (0x30) -> Camera responds from Port 40611
    Phase 2: Initialization (0xE0 + 0xE1) - Dual-phase wake sequence to discovered port
    Phase 3: Login (0xD0) - Direct authentication with BLE token to discovered port
    """

    # Constants
    PREFERRED_SOURCE_PORT = 5085
    DISCOVERY_PORT = 32108
    DEFAULT_LOGIN_PORT = 40611
    DISCOVERY_TIMEOUT = 2.0

    def __init__(self, camera_ip=None, logger=None):
        self.ip = camera_ip or config.CAM_IP
        self.port = config.CAM_PORT
        self.sock = None
        self.running = False
        self.keep_alive_thread = None
        self.logger = logger or logging.getLogger(__name__)
        self.session_token = None
        self.sequence_bytes = None
        self._state = CameraState.DISCONNECTED
        self._lock = threading.RLock()
        self.last_response_seq = None
        self.token_timestamp = None
        self.active_port = None
        self.login_attempts = 0
        self.max_login_attempts = 3
        self.login_port = None  # Stores the discovered port

        # FIX #42: Check firewall on init
        check_firewall(self.logger)

        # PPPP Integration
        self.pppp = PPPPProtocol(logger=self.logger)
        # FIX #59: Initialize Artemis sequence to 1 (start of sequence counter, matches Android log)
        self.artemis_seq = 1

    @property
    def state(self):
        with self._lock:
            return self._state

    def _set_state(self, new_state, reason=""):
        with self._lock:
            if self._state != new_state:
                self.logger.info(f"[STATE] {self._state.name} → {new_state.name} ({reason})")
                self._state = new_state

    def set_session_credentials(self, token: str, sequence: bytes, use_ble_dynamic: bool = True):
        """
        Set session credentials from BLE.
        
        FIX #23: Parse sequence bytes and set artemis_seq for Login.
        The sequence is typically 4 bytes in little-endian format.
        """
        with self._lock:
            self.session_token = token
            self.sequence_bytes = sequence if use_ble_dynamic else None
            self.token_timestamp = time.time()
            
            # FIX #59: We now start artemis_seq at 1 and increment.
            self.logger.info(
                f"[CREDENTIALS] Token={token[:20]}..., "
                f"Sequence={sequence.hex().upper() if sequence else 'NONE'}"
            )
            # Reset Artemis Seq to 1 on new credentials
            self.artemis_seq = 1

    def _socket_force_close(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            finally:
                self.sock = None

    def _create_socket(self, timeout: Optional[float] = None, use_fixed_port: bool = True) -> bool:
        """
        Creates and binds the UDP socket.
        Uses fixed port 5085 if available (like TrailCam Go), falls back to ephemeral.
        """
        # FIX #42: Explicit Interface Binding
        bind_ip = '0.0.0.0'
        wlan_ip = get_wlan_ip()
        if wlan_ip:
             self.logger.info(f"[SOCKET] Binding to camera AP interface: {wlan_ip}")
             bind_ip = wlan_ip
        else:
             self.logger.warning("[SOCKET] Could not detect camera AP IP, binding to 0.0.0.0")

        try:
            self._socket_force_close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                if hasattr(socket, 'SO_REUSEPORT'):
                    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    self.logger.debug("[SOCKET] SO_REUSEPORT enabled")
            except Exception:
                pass

            bind_port = 0
            if use_fixed_port:
                try:
                    self.sock.bind((bind_ip, self.PREFERRED_SOURCE_PORT))
                    bind_port = self.PREFERRED_SOURCE_PORT
                    self.logger.info(f"[SOCKET] ✓ Bound to fixed source port {bind_port}")
                except OSError as e:
                    self.logger.warning(f"[SOCKET] Cannot bind to fixed port {self.PREFERRED_SOURCE_PORT}: {e}")
                    self.logger.warning("[SOCKET] Falling back to ephemeral port")
                    self.sock.bind((bind_ip, 0))
            else:
                self.sock.bind((bind_ip, 0))

            # Update active port
            self.active_port = self.sock.getsockname()[1]
            if not bind_port:
                self.logger.info(f"[SOCKET] Using ephemeral source port {self.active_port}")

            timeout_val = timeout if timeout is not None else config.ARTEMIS_LOGIN_TIMEOUT
            self.sock.settimeout(timeout_val)
            return True

        except Exception as e:
            self.logger.error(f"[SOCKET] Creation failed: {e}")
            self._socket_force_close()
            return False

    def _discover_login_port(self) -> Optional[int]:
        """
        Sends LAN Search and waits for valid response to identify the camera's listening port.
        Returns the discovered port (e.g., 40611) or None if failed.
        """
        self.logger.info(f"[DISCOVERY] Sending LAN Search to {self.ip}:{self.DISCOVERY_PORT}")
        
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            lan_search = self.pppp.wrap_lan_search()

            # Send to Broadcast and Unicast
            self.sock.sendto(lan_search, ('255.255.255.255', self.DISCOVERY_PORT))
            self.sock.sendto(lan_search, (self.ip, self.DISCOVERY_PORT))

            # Wait for response
            with TimeoutContext(self.sock, self.DISCOVERY_TIMEOUT, self.logger):
                start_time = time.time()
                while time.time() - start_time < self.DISCOVERY_TIMEOUT:
                    try:
                        data, addr = self.sock.recvfrom(1024)
                        src_ip, src_port = addr

                        if len(data) < 8:
                            continue

                        # We expect 0x41 (LAN Search Response)
                        # Check magic F1
                        if data[0] != 0xF1:
                            continue

                        # Check Outer Type (0x41)
                        if data[1] == 0x41:
                             self.logger.info(f"[DISCOVERY] ✓ Received LAN Search Response from {src_ip}:{src_port}")
                             self.logger.debug(f"[DISCOVERY] Response hex: {data.hex()}")
                             return src_port

                    except socket.timeout:
                        break
                    except Exception as e:
                        self.logger.warning(f"[DISCOVERY] Packet error: {e}")

        except Exception as e:
            self.logger.error(f"[DISCOVERY] Failed during discovery: {e}")

        return None

    def _send_init_packets(self, dest_port: int) -> bool:
        """
        FIX #44: Send dual-phase initialization packets (0xE0 + 0xE1).
        """
        self._set_state(CameraState.INITIALIZING, "sending UDP init packets")
        self.logger.info(f"[INIT] Sending dual-phase wakeup to {self.ip}:{dest_port}...")
        
        try:
            with TimeoutContext(self.sock, config.ARTEMIS_LOGIN_TIMEOUT, self.logger):
                # Phase 1: 0xF1E0 packet
                init_ping = self.pppp.wrap_init_ping()
                self.sock.sendto(init_ping, (self.ip, dest_port))
                self.logger.debug(f"[INIT] Sent 0xE0 packet: {init_ping.hex()}")
                time.sleep(0.05)  # 50ms delay
                
                # Phase 2: 0xF1E1 packet
                init_secondary = self.pppp.wrap_init_secondary()
                self.sock.sendto(init_secondary, (self.ip, dest_port))
                self.logger.debug(f"[INIT] Sent 0xE1 packet: {init_secondary.hex()}")
                
                self.logger.info("[INIT] ✓ Dual-phase wakeup sent successfully")
                
                # FIX #48: Shorter wait (1s) before login
                # Android app shows ~0.5s delay between init and login
                self.logger.info("[INIT] Waiting 0.5s for camera UDP stack initialization...")
                time.sleep(0.5)
                
                return True
                
        except Exception as e:
            self.logger.warning(f"[INIT] Error during init phase: {e}")
            return True

    def _try_login_on_port(self, dest_port: int) -> bool:
        """
        Attempt login on the specific port.
        """
        self.logger.info(f"[LOGIN] Attempting login to {self.ip}:{dest_port} (Source: {self.active_port})...")
        
        if not self.session_token:
            self.logger.error("[LOGIN] No session token available")
            return False
        
        try:
            # Build Login Packet
            packet = ArtemisPacketBuilder.build_login_packet(
                self.session_token,
                self.artemis_seq,
                ble_seq=self.sequence_bytes
            )

            self.logger.info(f"[LOGIN] Sending to {self.ip}:{dest_port} (Seq: {self.artemis_seq})")
            
            # FIX #89: Drain socket buffer to remove delayed LAN Search responses (0x41)
            # which can cause race conditions.
            try:
                self.sock.settimeout(0.1)
                while True:
                    _ = self.sock.recv(4096)
            except (socket.timeout, BlockingIOError, OSError):
                pass
            finally:
                self.sock.settimeout(5.0)

            # FIX #48: Send login burst (3 packets like Android app)
            for attempt in range(3):
                self.sock.sendto(packet, (self.ip, dest_port))
                if attempt < 2:
                    time.sleep(0.1)
            
            # Wait for response
            with TimeoutContext(self.sock, 5.0, self.logger):
                start_time = time.time()
                while time.time() - start_time < 5.0:
                    try:
                        data, addr = self.sock.recvfrom(2048)

                        # Unwrap
                        try:
                            response = self.pppp.unwrap_pppp(data)
                        except Exception:
                            continue

                        # Ignore delayed LAN Search Response (0x41)
                        if response.get('outer_type') == 0x41:
                            self.logger.debug("[LOGIN] Ignoring delayed LAN Search Response")
                            continue

                        # Check for Success (0x01, 0x03, 0x04)
                        if response['subcommand'] in [0x01, 0x03, 0x04]:
                            self.logger.info(
                                f"[LOGIN] ✓ SUCCESS on port {dest_port} "
                                f"(Subcommand: 0x{response['subcommand']:02X})"
                            )

                            # Validate JSON for 0x03
                            if response['subcommand'] == 0x03:
                                 payload = response.get('payload', b'')
                                 self.logger.debug(f"[LOGIN] Payload: {payload}")

                            self._set_state(CameraState.AUTHENTICATED, f"port {dest_port}")
                            self.port = dest_port

                            # Sync PPPP sequence
                            self.pppp.reset_sequence(self.artemis_seq)
                            return True

                    except socket.timeout:
                        break

            self.logger.warning(f"[LOGIN] Timeout on port {dest_port}")
            return False

        except Exception as e:
            self.logger.error(f"[LOGIN] Error on port {dest_port}: {e}")
            return False

    def connect_with_retries(self) -> bool:
        """
        Optimized Connection Flow:
        1. Create Socket (Fixed Port 5085)
        2. LAN Search Discovery -> Get Port
        3. Wakeup (Init Packets) -> Discovered Port
        4. Login -> Discovered Port
        """
        self._set_state(CameraState.CONNECTING, "starting connection")
        max_retries = config.MAX_CONNECTION_RETRIES
        start_time_total = time.time()

        # Reset sequences
        self.pppp.reset_sequence(1)
        self.artemis_seq = 1

        for attempt in range(max_retries):
            elapsed = time.time() - start_time_total
            if elapsed > config.MAX_TOTAL_CONNECTION_TIME:
                self.logger.error("[CONNECT] Total connection time exceeded")
                break

            self.logger.info(f"[CONNECT] Attempt {attempt + 1}/{max_retries}")

            # 1. Create Socket (Try Fixed Port 5085)
            if not self._create_socket(timeout=5.0, use_fixed_port=True):
                time.sleep(1)
                continue

            # 2. Discovery
            discovered_port = self._discover_login_port()

            target_port = self.DEFAULT_LOGIN_PORT
            if discovered_port:
                self.logger.info(f"[CONNECT] Using discovered port: {discovered_port}")
                target_port = discovered_port
                self.login_port = discovered_port
            else:
                self.logger.warning(f"[CONNECT] Discovery failed, falling back to default port {target_port}")

            # 3. Wakeup
            if not self._send_init_packets(dest_port=target_port):
                self._socket_force_close()
                continue

            self.pppp.reset_sequence(1)

            # 4. Login (No multi-port probing, just the target port)
            if self._try_login_on_port(target_port):
                self.start_heartbeat()
                return True
            else:
                self.logger.warning(f"[CONNECT] Login failed on port {target_port}")
                self._socket_force_close()

            # Backoff
            backoff = config.RETRY_BACKOFF_SEQUENCE[
                min(attempt, len(config.RETRY_BACKOFF_SEQUENCE) - 1)
            ]
            self.logger.info(f"[CONNECT] Waiting {backoff}s before retry...")
            time.sleep(backoff)

        self._set_state(CameraState.CONNECTION_FAILED, "all retries exhausted")
        return False

    def connect(self):
        return self.connect_with_retries()

    def close(self):
        self.running = False
        self._socket_force_close()
        self._set_state(CameraState.DISCONNECTED, "closed")

    def login(self, variant: str = 'BLE_DYNAMIC') -> bool:
        return self._try_login_on_port(self.port)

    def start_heartbeat(self):
        with self._lock:
            if not self.running:
                self.running = True
                self.keep_alive_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
                self.keep_alive_thread.start()
                self.logger.info("[HEARTBEAT] Started heartbeat thread")

    def _heartbeat_loop(self):
        while self.running:
            try:
                if self._state == CameraState.AUTHENTICATED:
                    json_payload = json.dumps({"cmdId": 525}).encode('utf-8')
                    packet = self.pppp.wrap_heartbeat(json_payload)

                    if self.sock:
                        self.sock.sendto(packet, (self.ip, self.port))
                        self.logger.debug(f"[HEARTBEAT] Sent seq {self.pppp.get_sequence()}")
                time.sleep(config.ARTEMIS_KEEPALIVE_INTERVAL)
            except Exception as e:
                self.logger.error(f"[HEARTBEAT] Error: {e}")
                break
