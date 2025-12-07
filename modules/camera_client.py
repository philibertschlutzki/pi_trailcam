import socket
import time
import logging
import struct
import threading
from enum import Enum, auto
from typing import Optional, Tuple
import config
from modules.pppp_wrapper import PPPPWrapper

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
}

class CameraState(Enum):
    DISCONNECTED = auto()
    DISCOVERING = auto()
    DISCOVERED = auto()
    CONNECTING = auto()
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
    Client for cameras with the Artemis protocol.
    
    FIX #21: Discovery Packet Format
    Official App uses a minimal F1 E0 00 00 packet for discovery.
    No inner D1 header, no payload. Just 4 bytes.
    
    FIX #22: PPPP Sequence Management
    PPPP sequence number is per-session, not per-attempt.
    Resetting on each port retry caused all packets to have Seq=0x0001.
    """

    def __init__(self, camera_ip=None, logger=None):
        self.ip = camera_ip or config.CAM_IP
        self.port = config.CAM_PORT
        self.sock = None
        # self.seq_num = 1  # DEPRECATED: Handled by PPPPWrapper
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

        # PPPP Integration
        self.pppp = PPPPWrapper(logger=self.logger)
        self.artemis_seq = 0x001B  # Initial Artemis Sequence (will be incremented)

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
        with self._lock:
            self.session_token = token
            self.sequence_bytes = sequence if use_ble_dynamic else None
            self.token_timestamp = time.time()
            self.logger.info(
                f"[CREDENTIALS] Token={token[:20]}..., "
                f"Sequence={sequence.hex().upper() if sequence else 'NONE'}"
            )

    def _socket_force_close(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            finally:
                self.sock = None

    def _create_socket(self, port: int, timeout: Optional[float] = None) -> bool:
        self.logger.info(
            f"[SOCKET] Binding local UDP source port {port} → Destination {self.ip}:{config.CAM_PORT}"
        )
        try:
            self._socket_force_close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('', port))
            timeout_val = timeout if timeout is not None else config.ARTEMIS_LOGIN_TIMEOUT
            self.sock.settimeout(timeout_val)
            self.seq_num = 1
            self.active_port = port
            return True
        except Exception as e:
            self.logger.error(f"[SOCKET] Creation failed: {e}")
            self._socket_force_close()
            return False

    def discovery_phase(self) -> bool:
        """
        Sends the PPPP wrapped discovery packet.
        
        FIX #22: Do NOT reset pppp_seq here!
        PPPP sequence is per-session, not per-attempt.
        Resetting caused all discovery packets to have Seq=0x0001
        which the camera rejects as duplicate/corrupted.
        """
        self._set_state(CameraState.DISCOVERING, "starting discovery")
        self.logger.info("[DISCOVERY] Sending PPPP Discovery...")

        # FIX #22: REMOVED - Do not reset here!
        # self.pppp.reset_sequence(1)
        
        # DEBUG: Log current PPPP Seq before wrapping
        current_pppp_seq = self.pppp.get_sequence()
        self.logger.info(f"[DISCOVERY DEBUG] PPPP Seq before wrap: 0x{current_pppp_seq:04X}")
        
        # Create wrapped discovery packet
        packet = self.pppp.wrap_discovery(self.artemis_seq)
        
        # DEBUG: Log PPPP Seq after wrapping
        new_pppp_seq = self.pppp.get_sequence()
        self.logger.info(f"[DISCOVERY DEBUG] PPPP Seq after wrap: 0x{new_pppp_seq:04X}")
        self.logger.info(f"[DISCOVERY] Sent packet: {packet.hex()}")

        # Increment Artemis sequence
        self.artemis_seq += 1
        
        start_time = time.time()
        
        try:
            with TimeoutContext(self.sock, config.ARTEMIS_DISCOVERY_TIMEOUT, self.logger):
                self.sock.sendto(packet, (self.ip, self.port))
                self.logger.debug(f"[DISCOVERY] Sent: {packet.hex()}")
                
                # Expect response
                data, addr = self.sock.recvfrom(2048)
                duration = time.time() - start_time
                
                # Unwrap and validate
                try:
                    response = self.pppp.unwrap_pppp(data)
                    if response['subcommand'] == 0x01: # Discovery ACK
                        self.logger.info(f"[DISCOVERY] ✓ Response: {data.hex()} from {addr} in {duration:.2f}s")
                        self._set_state(CameraState.DISCOVERED, f"on source port {self.active_port}")
                        return True
                    else:
                        self.logger.warning(f"[DISCOVERY] Unexpected subcommand: 0x{response['subcommand']:02X}")
                except ValueError as ve:
                    self.logger.error(f"[DISCOVERY] Invalid response: {ve}")

                return False
                
        except socket.timeout:
            duration = time.time() - start_time
            self.logger.warning(f"[DISCOVERY] ✗ Timeout after {duration:.2f}s")
            return False
        except Exception as e:
            self.logger.error(f"[DISCOVERY] Error: {e}")
            return False

    def connect_with_retries(self) -> bool:
        self._set_state(CameraState.CONNECTING, "starting retry loop")
        ports = config.DEVICE_PORTS
        max_retries = config.MAX_CONNECTION_RETRIES
        start_time_total = time.time()

        # FIX #22: Initialize PPPP sequence once for the entire connection session
        self.logger.info("[CONNECT] Resetting PPPP sequence to 1")
        self.pppp.reset_sequence(1)

        for attempt in range(max_retries):
            elapsed = time.time() - start_time_total
            if elapsed > config.MAX_TOTAL_CONNECTION_TIME:
                self._set_state(CameraState.CONNECTION_FAILED, "total timeout")
                return False

            self.logger.info(f"[CONNECT] Attempt {attempt + 1}/{max_retries}")

            for port in ports:
                if self._create_socket(port, timeout=config.ARTEMIS_DISCOVERY_TIMEOUT):
                    if self.discovery_phase():
                        self.logger.info(f"[CONNECT] ✓ Connected on source port {port}")
                        self._set_state(CameraState.CONNECTED, f"source port {port}")
                        # Set login timeout
                        self.sock.settimeout(config.ARTEMIS_LOGIN_TIMEOUT)
                        return True
                    else:
                        self._socket_force_close()

            time.sleep(config.RETRY_BACKOFF_SEQUENCE[min(attempt, len(config.RETRY_BACKOFF_SEQUENCE)-1)])

        self._set_state(CameraState.CONNECTION_FAILED, "all retries exhausted")
        return False

    def connect(self):
        return self.connect_with_retries()

    def close(self):
        self.running = False
        self._socket_force_close()
        self._set_state(CameraState.DISCONNECTED, "closed")


    def _build_login_payload(self, variant: str = 'MYSTERY_09_01') -> bytes:
        if not self.session_token: raise ValueError("No token")
        
        artemis = b'ARTEMIS\x00'
        version = b'\x02\x00\x00\x00'
        
        if variant == 'BLE_DYNAMIC' and self.sequence_bytes:
            sequence = self.sequence_bytes
        else:
            sequence = MYSTERY_VARIANTS.get(variant, MYSTERY_VARIANTS['MYSTERY_09_01'])
            
        token_len = struct.pack('<I', len(self.session_token))
        token_bytes = self.session_token.encode('ascii') + b'\x00'
        
        return artemis + version + sequence + token_len + token_bytes

    def login(self, variant: str = 'MYSTERY_09_01') -> bool:
        if not self.session_token: return False
        
        try:
            # Build Artemis payload
            artemis_payload = self._build_login_payload(variant)

            # Wrap in PPPP
            packet = self.pppp.wrap_login(artemis_payload)

            self.logger.info(f"[LOGIN] Sending Login (Variant: {variant})...")
            self.sock.sendto(packet, (self.ip, self.port))
            
            # Receive response
            data, _ = self.sock.recvfrom(2048)

            # Unwrap
            response = self.pppp.unwrap_pppp(data)
            
            if response['subcommand'] == 0x04: # Login ACK
                self.logger.info("[LOGIN] ✓ SUCCESS")
                self._set_state(CameraState.AUTHENTICATED, f"variant {variant}")
                self.start_heartbeat()
                return True
            else:
                self.logger.warning(f"[LOGIN] Failed. Subcommand: 0x{response['subcommand']:02X}")
                return False

        except socket.timeout:
            self.logger.error("[LOGIN] Timeout")
            return False
        except Exception as e:
            self.logger.error(f"[LOGIN] Error: {e}")
            return False

    def start_heartbeat(self):
        with self._lock:
            if not self.running:
                self.running = True
                self.keep_alive_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
                self.keep_alive_thread.start()

    def _heartbeat_loop(self):
        while self.running:
            try:
                if self._state == CameraState.AUTHENTICATED:
                    packet = self.pppp.wrap_heartbeat(self.artemis_seq)
                    if self.sock:
                        self.sock.sendto(packet, (self.ip, self.port))
                        self.logger.debug(f"[HEARTBEAT] Sent seq {self.artemis_seq}")
                time.sleep(config.ARTEMIS_KEEPALIVE_INTERVAL)
            except Exception as e:
                self.logger.error(f"[HEARTBEAT] Error: {e}")
                break
