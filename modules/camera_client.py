import socket
import time
import logging
import struct
import threading
from enum import Enum, auto
from typing import Optional, Tuple
import config

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
    """

    def __init__(self, camera_ip=None, logger=None):
        self.ip = camera_ip or config.CAM_IP
        self.port = config.CAM_PORT
        self.sock = None
        self.seq_num = 1
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
        Sends the OFFICIAL discovery packet (0xF1E00000).
        
        Based on tcpdump analysis:
        17:55:23.927 IP ... > ...40611: UDP, length 4
        0x0000: f1e0 0000
        
        This is a minimal "Knock" packet without ARTEMIS inner header.
        """
        self._set_state(CameraState.DISCOVERING, "starting discovery")
        self.logger.info("[DISCOVERY] Sending F1 E0 00 00 Ping...")
        
        # FIX #21: Use exact byte sequence from tcpdump
        # F1 (Magic) E0 (Type) 00 00 (Length 0)
        discovery_packet = b'\xF1\xE0\x00\x00'
        
        start_time = time.time()
        
        try:
            with TimeoutContext(self.sock, config.ARTEMIS_DISCOVERY_TIMEOUT, self.logger):
                self.sock.sendto(discovery_packet, (self.ip, self.port))
                self.logger.debug(f"[DISCOVERY] Sent: {discovery_packet.hex()}")
                
                # Expect response
                data, addr = self.sock.recvfrom(2048)
                duration = time.time() - start_time
                
                self.logger.info(f"[DISCOVERY] ✓ Response: {data.hex()} from {addr} in {duration:.2f}s")
                self._set_state(CameraState.DISCOVERED, f"on source port {self.active_port}")
                return True
                
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

    def _get_inner_header(self, pkt_type: int) -> bytes:
        magic = 0xD1
        header = struct.pack('>BBH', magic, pkt_type, self.seq_num)
        return header

    def _get_outer_header(self, inner_packet: bytes, outer_type: int) -> bytes:
        magic = 0xF1
        length = len(inner_packet)
        return struct.pack('>BBH', magic, outer_type, length)

    def send_packet(self, payload: bytes, inner_type: int = 0x00, outer_type: int = 0xD1, 
                   wait_for_response: bool = True, description: str = "Unknown") -> Optional[bytes]:
        if not self.sock: return None
        try:
            inner = self._get_inner_header(inner_type) + payload
            outer = self._get_outer_header(inner, outer_type)
            packet = outer + inner
            
            self.logger.debug(f"[SEND] {description} ({len(packet)} bytes)")
            self.sock.sendto(packet, (self.ip, self.port))
            self.seq_num += 1
            
            if wait_for_response:
                data, _ = self.sock.recvfrom(2048)
                return data
            return True
        except Exception as e:
            self.logger.error(f"[SEND] Error: {e}")
            return None

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
        
        # FIX #21: Reset sequence to 5 for login packet as seen in tcpdump
        # D1 00 00 05 -> Seq 5
        self.seq_num = 5
        
        try:
            payload = self._build_login_payload(variant)
            self.logger.info(f"[LOGIN] Sending Login (Variant: {variant})...")
            
            response = self.send_packet(
                payload, inner_type=0x00, outer_type=0xD0, description="Login"
            )
            
            if response and len(response) > 4:
                self.logger.info("[LOGIN] ✓ SUCCESS")
                self._set_state(CameraState.AUTHENTICATED, f"variant {variant}")
                self.start_heartbeat()
                return True
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
                    self.send_packet(b'\x00\x00', inner_type=0x01, outer_type=0xD1, 
                                   wait_for_response=False, description="Heartbeat")
                time.sleep(config.ARTEMIS_KEEPALIVE_INTERVAL)
            except:
                break
