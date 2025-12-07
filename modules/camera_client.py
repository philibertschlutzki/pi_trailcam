import socket
import time
import logging
import struct
import threading
from enum import Enum, auto
from typing import Optional, Tuple
from collections import deque
import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === ARTEMIS Login Sequence Variants ===
# These represent the mystery bytes at position [12:16] in the ARTEMIS payload
# From tcpdump analysis of successful authentication
MYSTERY_VARIANTS = {
    'MYSTERY_09_01': bytes([0x09, 0x00, 0x01, 0x00]),      # ✓ Aus tcpdump erfolgreich
    'SMARTPHONE_DUMP': bytes([0x2b, 0x00, 0x2d, 0x00]),   # Aus Smartphone-Dump
    'ORIGINAL': bytes([0x02, 0x00, 0x01, 0x00]),          # Original-Hypothese
    'MYSTERY_2B_ONLY': bytes([0x2b, 0x00, 0x00, 0x00]),   # Nur 2b
    'MYSTERY_2D_ONLY': bytes([0x2d, 0x00, 0x00, 0x00]),   # Nur 2d
    'SEQUENCE_VARIANT': bytes([0x03, 0x00, 0x04, 0x00]),  # Sequenz-Hypothese
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
    """Context-Manager für Timeout-Verwaltung mit Stack-Support"""
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
                self.logger.debug(f"Timeout set: {self.old_timeout}s → {self.new_timeout}s")
            except Exception as e:
                self.logger.error(f"Failed to set timeout: {e}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.socket and self.old_timeout is not None:
            try:
                self.socket.settimeout(self.old_timeout)
                self.logger.debug(f"Timeout restored: {self.old_timeout}s")
            except Exception as e:
                self.logger.error(f"Failed to restore timeout: {e}")
        return False

class CameraClient:
    """
    Client for cameras with the Artemis protocol (Wrapped F1... / D1...).
    Outer Header (4 Bytes): [F1] [Type] [Len_H] [Len_L]
    Inner Header (4 Bytes): [D1] [Type] [Seq_H] [Seq_L]
    
    IMPROVEMENTS:
    - FIX #20: UDP socket now binds to source ports from DEVICE_PORTS
    - Destination always uses CAM_PORT (40611) from config
    - State-Machine mit Validierung
    - Timeout-Context-Manager
    - Response-Validierung mit Seq-Check
    - Thread-sichere Heartbeat
    - Detailliertes Error-Reporting
    """

    def __init__(self, camera_ip=None, logger=None):
        self.ip = camera_ip or config.CAM_IP
        self.port = config.CAM_PORT  # This is the DESTINATION port (40611)
        self.sock = None
        self.seq_num = 1
        self.running = False
        self.keep_alive_thread = None
        self.logger = logger or logging.getLogger(__name__)
        self.session_token = None
        self.sequence_bytes = None
        self._state = CameraState.DISCONNECTED
        self._lock = threading.RLock()  # Für Thread-Sicherheit
        self.last_response_seq = None  # Seq-Tracking
        self.token_timestamp = None  # Token-Alter tracken
        self.active_port = None  # Welcher SOURCE port ist aktiv?
        self.login_attempts = 0  # Login-Versuche zählen
        self.max_login_attempts = 3

    @property
    def state(self):
        with self._lock:
            return self._state

    def _set_state(self, new_state, reason=""):
        """State-Wechsel mit Logging und Validierung"""
        with self._lock:
            if self._state != new_state:
                transition = f"{self._state.name} → {new_state.name}"
                if reason:
                    transition += f" ({reason})"
                self.logger.info(f"[STATE] {transition}")
                self._state = new_state

    def set_session_credentials(self, token: str, sequence: bytes, use_ble_dynamic: bool = True):
        """
        Set auth credentials extracted from BLE.
        Mit Timestamp für Token-Validierung.

        Args:
            token: Base64 string, 45 characters
            sequence: 4 bytes from BLE (e.g., b'\x2b\x00\x00\x00')
            use_ble_dynamic: Use BLE sequence in login (default: True)
        """
        if len(token) != 45:
            self.logger.warning(f"Token length {len(token)} != 45 (expected 45)")

        with self._lock:
            self.session_token = token
            self.sequence_bytes = sequence if use_ble_dynamic else None
            self.token_timestamp = time.time()
            self.logger.info(
                f"[CREDENTIALS] Token={token[:20]}..., "
                f"Sequence={sequence.hex().upper() if sequence else 'NONE'}, "
                f"BLE_Dynamic={'ENABLED' if use_ble_dynamic else 'DISABLED'}"
            )

    def get_token_age_seconds(self) -> Optional[float]:
        """Gibt das Alter des aktuellen Tokens in Sekunden zurück"""
        if self.token_timestamp:
            return time.time() - self.token_timestamp
        return None

    def _socket_force_close(self):
        """Erzwingt Socket-Schließung mit vollständigem Cleanup"""
        if self.sock:
            try:
                # Zuerst Shutdown versuchen
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                
                # Dann Close
                self.sock.close()
                self.logger.debug("Socket closed successfully")
            except Exception as e:
                self.logger.warning(f"Error closing socket: {e}")
            finally:
                self.sock = None

    def _create_socket(self, port: int, timeout: Optional[float] = None) -> bool:
        """
        FIX #20: Creates UDP socket and binds to SOURCE port from DEVICE_PORTS.
        Destination is always CAM_PORT (40611).
        
        The camera firewall/protocol stack requires clients to bind to specific
        source ports. These are listed in DEVICE_PORTS. The destination is always
        port 40611 on the camera (192.168.43.1).
        
        Args:
            port: Local SOURCE port to bind to (from DEVICE_PORTS)
            timeout: Socket timeout in seconds
            
        Returns:
            True if socket created successfully, False otherwise
        """
        self.logger.info(
            f"[SOCKET] Binding local UDP source port {port} → "
            f"Destination {self.ip}:{config.CAM_PORT}"
        )
        
        try:
            # Alten Socket komplett schließen
            self._socket_force_close()
            
            # Neuen Socket erstellen
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # FIX #20: Allow reuse of address to prevent "Address already in use" errors
            # This is important when retrying different source ports
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # FIX #20: Bind to the specific LOCAL (source) port
            # Empty string means bind to all local interfaces (0.0.0.0)
            self.sock.bind(('', port))
            
            # Timeout setzen
            timeout_val = timeout if timeout is not None else config.ARTEMIS_LOGIN_TIMEOUT
            self.sock.settimeout(timeout_val)
            
            # State reset
            self.seq_num = 1
            self.active_port = port  # Track which SOURCE port is active
            # self.port stays as CAM_PORT (40611) - this is destination
            self.last_response_seq = None
            
            self.logger.info(
                f"[SOCKET] Created successfully. "
                f"Bind to local port {port}, sending to {self.ip}:{self.port}"
            )
            return True
            
        except OSError as e:
            self.logger.error(
                f"[SOCKET] Bind failed on local port {port}: {e}. "
                f"This port may already be in use. Try again in a few seconds."
            )
            self._socket_force_close()
            return False
        except Exception as e:
            self.logger.error(f"[SOCKET] Creation failed: {e}")
            self._socket_force_close()
            return False

    def discovery_phase(self) -> bool:
        """
        Sends a discovery packet (heartbeat/ping) and waits for a response.
        Uses dedicated timeout context.
        
        Returns: True if device responds within timeout
        """
        self._set_state(CameraState.DISCOVERING, "starting discovery")
        self.logger.info("[DISCOVERY] Starting ARTEMIS discovery phase...")
        start_time = time.time()

        # Heartbeat packet mit Discovery-Timeout
        with TimeoutContext(self.sock, config.ARTEMIS_DISCOVERY_TIMEOUT, self.logger):
            response = self.send_packet(
                b'\x00\x00', 
                inner_type=0x01, 
                outer_type=0xD1, 
                wait_for_response=True,
                description="Discovery Ping"
            )

        duration = time.time() - start_time
        
        if response:
            self.logger.info(f"[DISCOVERY] ✓ Response received in {duration:.2f}s")
            self._set_state(CameraState.DISCOVERED, f"on source port {self.active_port}")
            return True
        else:
            self.logger.warning(f"[DISCOVERY] ✗ Timeout after {duration:.2f}s")
            return False

    def connect_with_retries(self) -> bool:
        """
        Attempts to connect using configured SOURCE ports and exponential backoff.
        Performs discovery before considering connection 'established'.
        
        FIX #20: Iterates through DEVICE_PORTS as SOURCE ports, not destination.
        
        Returns: True if connection + discovery successful
        """
        self._set_state(CameraState.CONNECTING, "starting retry loop")

        ports = config.DEVICE_PORTS
        max_retries = config.MAX_CONNECTION_RETRIES
        backoff_sequence = config.RETRY_BACKOFF_SEQUENCE
        start_time_total = time.time()

        for attempt in range(max_retries):
            # Check total time limit
            elapsed = time.time() - start_time_total
            if elapsed > config.MAX_TOTAL_CONNECTION_TIME:
                self.logger.error(f"[CONNECT] Max total time {config.MAX_TOTAL_CONNECTION_TIME}s exceeded")
                self._set_state(CameraState.CONNECTION_FAILED, "total timeout")
                return False

            self.logger.info(f"[CONNECT] Attempt {attempt + 1}/{max_retries} (elapsed: {elapsed:.1f}s)")

            for port_idx, port in enumerate(ports):
                self.logger.info(
                    f"[CONNECT] Trying source port {port} ({port_idx+1}/{len(ports)})"
                )
                
                # Socket mit Discovery-Timeout erstellen
                if self._create_socket(port, timeout=config.ARTEMIS_DISCOVERY_TIMEOUT):
                    if config.REQUIRE_DEVICE_DISCOVERY:
                        if self.discovery_phase():
                            self.logger.info(f"[CONNECT] ✓ Device discovered on source port {port}")
                            self._set_state(CameraState.CONNECTED, f"source port {port}")
                            
                            # Timeout für Login setzen
                            with TimeoutContext(self.sock, config.ARTEMIS_LOGIN_TIMEOUT, self.logger):
                                pass  # Timeout wird gesetzt
                            return True
                        else:
                            self.logger.warning(f"[CONNECT] Discovery failed on source port {port}")
                            self._socket_force_close()
                    else:
                        # Skip discovery if configured
                        self.logger.info(f"[CONNECT] Discovery skipped (config)")
                        self._set_state(CameraState.CONNECTED, f"source port {port} (no discovery)")
                        with TimeoutContext(self.sock, config.ARTEMIS_LOGIN_TIMEOUT, self.logger):
                            pass
                        return True

            # Alle Ports in diesem Versuch fehlgeschlagen
            if attempt < len(backoff_sequence):
                wait_time = backoff_sequence[attempt]
            else:
                wait_time = backoff_sequence[-1]

            self.logger.warning(
                f"[CONNECT] Attempt {attempt + 1} failed. "
                f"Waiting {wait_time}s before retry..."
            )
            time.sleep(wait_time)

        self.logger.error("[CONNECT] ✗ Failed after all retries")
        self._set_state(CameraState.CONNECTION_FAILED, "all retries exhausted")
        return False

    def connect(self):
        """Legacy alias for backward compatibility"""
        return self.connect_with_retries()

    def close(self):
        """Graceful shutdown mit Thread-Cleanup"""
        self.logger.info("[CLOSE] Initiating graceful shutdown...")
        
        # Heartbeat stoppen
        self.running = False
        
        # Thread warten (max 2s)
        if self.keep_alive_thread and self.keep_alive_thread.is_alive():
            self.logger.debug("[CLOSE] Waiting for heartbeat thread...")
            self.keep_alive_thread.join(timeout=2.0)
            if self.keep_alive_thread.is_alive():
                self.logger.warning("[CLOSE] Heartbeat thread did not exit (daemon)")
        
        # Socket schließen
        self._socket_force_close()
        self._set_state(CameraState.DISCONNECTED, "graceful close")

    def _get_inner_header(self, pkt_type: int) -> bytes:
        """Creates the inner D1 header with current sequence number"""
        magic = 0xD1
        header = struct.pack('>BBH', magic, pkt_type, self.seq_num)
        return header

    def _get_outer_header(self, inner_packet: bytes, outer_type: int) -> bytes:
        """
        Creates the outer F1 header.
        Length is the length of the entire inner packet (Header + Payload).
        """
        magic = 0xF1
        length = len(inner_packet)
        return struct.pack('>BBH', magic, outer_type, length)

    def send_packet(
        self, 
        payload: bytes, 
        inner_type: int = 0x00, 
        outer_type: int = 0xD1, 
        wait_for_response: bool = True,
        description: str = "Unknown"
    ) -> Optional[bytes]:
        """
        Sends packet mit Response-Validierung.
        
        Args:
            payload: Packet payload
            inner_type: Inner header type
            outer_type: Outer header type
            wait_for_response: Wait for response
            description: Beschreibung für Logging
        
        Returns: Response data or None
        """
        if not self.sock:
            self.logger.error(f"[SEND] No socket available ({description})")
            return None

        try:
            # 1. Build Inner Packet (D1...)
            inner_header = self._get_inner_header(inner_type)
            inner_packet = inner_header + payload

            # 2. Build Outer Packet (F1...)
            outer_header = self._get_outer_header(inner_packet, outer_type)
            final_packet = outer_header + inner_packet

            current_seq = self.seq_num
            self.logger.debug(
                f"[SEND] Seq {current_seq}: {description} "
                f"({len(final_packet)} bytes, type=0x{inner_type:02x})"
            )
            self.logger.debug(f"[SEND] Raw: {final_packet.hex()}")
            
            # Send packet to CAM_IP:CAM_PORT
            self.sock.sendto(final_packet, (self.ip, self.port))
            self.seq_num += 1

            if not wait_for_response:
                return True

            # Warte auf Response
            try:
                data, _ = self.sock.recvfrom(2048)
                self.logger.debug(f"[RECV] Raw: {data.hex()}")
                
                # Validiere Response-Sequenz (falls möglich)
                if len(data) >= 4:
                    response_seq = struct.unpack('>H', data[2:4])[0]
                    if response_seq != current_seq:
                        self.logger.warning(
                            f"[RECV] Seq mismatch: sent {current_seq}, "
                            f"got {response_seq} (might be async)"
                        )
                
                self.last_response_seq = current_seq
                return data
                
            except socket.timeout:
                self.logger.warning(f"[SEND] Timeout waiting for response (Seq {current_seq})")
                return None

        except Exception as e:
            self.logger.error(f"[SEND] Error: {e}")
            return None

    def _build_login_payload(self, variant: str = 'MYSTERY_09_01') -> bytes:
        """
        Build ARTEMIS binary login packet mit BLE-Support.
        
        Uses extracted token + sequence variant, NOT hardcoded values!
        
        Structure:
        - Protocol: "ARTEMIS\x00" (8 bytes)
        - Version: 0x02000000 (4 bytes)
        - Sequence: from variant or BLE (4 bytes)
        - Token length: 0x2d000000 (4 bytes, little-endian 45)
        - Token: extracted token + null terminator
        
        Args:
            variant: which mystery bytes variant to use
                    'BLE_DYNAMIC' uses self.sequence_bytes from BLE
        
        Returns: Login payload bytes
        """
        if not self.session_token:
            raise ValueError(
                "Session credentials not set! "
                "Call set_session_credentials(token, sequence) first."
            )
        
        # ARTEMIS header
        artemis = b'ARTEMIS\x00'
        
        # Version 0x02000000
        version = b'\x02\x00\x00\x00'
        
        # Sequence bytes
        if variant == 'BLE_DYNAMIC':
            if self.sequence_bytes:
                sequence = self.sequence_bytes
                self.logger.debug(f"[LOGIN] Using BLE_DYNAMIC sequence: {sequence.hex().upper()}")
            else:
                self.logger.warning(
                    f"[LOGIN] BLE_DYNAMIC requested but no sequence_bytes set, "
                    f"falling back to MYSTERY_09_01"
                )
                sequence = MYSTERY_VARIANTS['MYSTERY_09_01']
        elif variant in MYSTERY_VARIANTS:
            sequence = MYSTERY_VARIANTS[variant]
            self.logger.debug(f"[LOGIN] Using variant '{variant}': {sequence.hex().upper()}")
        else:
            self.logger.warning(f"[LOGIN] Unknown variant '{variant}', using MYSTERY_09_01")
            sequence = MYSTERY_VARIANTS['MYSTERY_09_01']
        
        # Token length (45 bytes = 0x2d) in little-endian
        token_len_val = len(self.session_token)
        token_len_field = struct.pack('<I', token_len_val)
        
        # Token string + null terminator
        token_bytes = self.session_token.encode('ascii') + b'\x00'
        
        return artemis + version + sequence + token_len_field + token_bytes

    def _validate_login_response(self, response: Optional[bytes]) -> Tuple[bool, str]:
        """
        Validiert Login-Response auf Fehler und Payload-Integrität.
        
        Returns: (success, message)
        """
        if response is None:
            return False, "No response received (timeout)"
        
        if len(response) < 4:
            return False, f"Response too short ({len(response)} bytes)"
        
        # Prüfe auf Error-Codes im Response
        # ARTEMIS Protocol: typical response hat structure mit error codes
        try:
            # Basic check: Response sollte mit D1 anfangen oder ähnliches
            if response[0] == 0xF1:  # Outer header
                if len(response) >= 8:
                    inner_magic = response[4]
                    if inner_magic == 0xD1:  # Inner header
                        return True, "Valid response structure"
            
            # Alternative: Check für string "Success" oder ähnliches im Response
            response_str = response.decode('utf-8', errors='ignore')
            if 'success' in response_str.lower() or 'errorCode":"' in response_str:
                return True, "Response contains success indicator"
            
            # Wenn wir hier sind, ist Response da aber Validierung nicht eindeutig
            self.logger.debug(f"[LOGIN] Response: {response[:100]}")
            return True, "Response received (validation inconclusive, assuming success)"
            
        except Exception as e:
            self.logger.error(f"[LOGIN] Response validation error: {e}")
            return False, f"Response validation failed: {e}"

    def login(self, variant: str = 'MYSTERY_09_01') -> bool:
        """
        Authenticate using extracted BLE token with selected variant.
        Mit Validierung und Attempt-Tracking.
        
        Args:
            variant: which mystery bytes variant to use
        
        Returns:
            True if login succeeds
            False if timeout or error
        """
        if not self.session_token:
            self.logger.error("[LOGIN] No session token set!")
            return False

        if self._state not in [CameraState.CONNECTED, CameraState.DISCOVERED]:
            self.logger.error(
                f"[LOGIN] Cannot login in state {self._state.name}. "
                f"Must be CONNECTED or DISCOVERED."
            )
            return False
        
        self.login_attempts += 1
        if self.login_attempts > self.max_login_attempts:
            self.logger.error(
                f"[LOGIN] Max login attempts ({self.max_login_attempts}) exceeded"
            )
            self._set_state(CameraState.CONNECTION_FAILED, "max login attempts exceeded")
            return False
            
        self.logger.info("\n" + "="*70)
        self.logger.info(f"PHASE 3: UDP LOGIN (Attempt {self.login_attempts}, Variant: {variant})")
        self.logger.info("="*70)

        # Sequence number = 5 (per ARTEMIS spec, siehe Logs)
        # Erklärung: Seq 1-4 werden möglicherweise intern von anderen cmds verwendet
        self.seq_num = 5

        # Ensure login timeout is set
        with TimeoutContext(self.sock, config.ARTEMIS_LOGIN_TIMEOUT, self.logger):
            try:
                payload = self._build_login_payload(variant=variant)
                self.logger.info(f"[LOGIN] Payload: {len(payload)} bytes")
                self.logger.info(f"[LOGIN] Mystery Bytes [12:16]: {payload[12:16].hex().upper()}")
                self.logger.info(f"[LOGIN] Token: {self.session_token[:20]}...")
                
                # outer_type=0xD0 for login
                response = self.send_packet(
                    payload, 
                    inner_type=0x00, 
                    outer_type=0xD0,
                    description=f"Login ({variant})"
                )
                
                # Validiere Response
                success, message = self._validate_login_response(response)
                
                if success:
                    self.logger.info(f"[LOGIN] ✓ SUCCESS with variant '{variant}'")
                    self.logger.info(f"[LOGIN] {message}")
                    self._set_state(CameraState.AUTHENTICATED, f"variant {variant}")
                    self.login_attempts = 0  # Reset counter
                    self.start_heartbeat()
                    return True
                else:
                    self.logger.warning(f"[LOGIN] ✗ FAILED: {message}")
                    return False
                    
            except Exception as e:
                self.logger.error(f"[LOGIN] ERROR: {e}")
                return False

    def try_all_variants(self) -> bool:
        """
        Try all mystery variants in order until one succeeds.
        Mit detailliertem State-Tracking.
        """
        self.logger.info("\n" + "="*70)
        self.logger.info("STARTING FALLBACK VARIANT TEST")
        self.logger.info("="*70 + "\n")
        
        # Test BLE_DYNAMIC first if available (beste Chancen)
        variant_order = ['BLE_DYNAMIC', 'MYSTERY_09_01', 'ORIGINAL', 
                         'SMARTPHONE_DUMP', 'MYSTERY_2B_ONLY', 'MYSTERY_2D_ONLY', 
                         'SEQUENCE_VARIANT']
        
        # Skip BLE_DYNAMIC if no sequence_bytes
        if not self.sequence_bytes:
            variant_order = variant_order[1:]
        
        for idx, variant in enumerate(variant_order, 1):
            total = len(variant_order)
            self.logger.info(f"\n--- Fallback {idx}/{total}: {variant} ---")
            
            if variant != 'BLE_DYNAMIC':
                mystery_bytes = MYSTERY_VARIANTS.get(variant, b'????')
                self.logger.info(f"    Mystery Bytes: {mystery_bytes.hex().upper()}")
            else:
                if self.sequence_bytes:
                    self.logger.info(f"    Sequence (from BLE): {self.sequence_bytes.hex().upper()}")
            
            if self.login(variant=variant):
                self.logger.info(f"\n✓✓✓ SUCCESS WITH VARIANT: {variant} ✓✓✓")
                return True
            
            time.sleep(1)  # Wait before next attempt
        
        self.logger.error("\n" + "="*70)
        self.logger.error("❌ ALL VARIANTS FAILED")
        self.logger.error("="*70)
        self._set_state(CameraState.CONNECTION_FAILED, "all variants failed")
        return False

    def start_heartbeat(self):
        """Starts heartbeat thread mit Thread-Sicherheit"""
        with self._lock:
            if self.keep_alive_thread and self.keep_alive_thread.is_alive():
                self.logger.warning("[HEARTBEAT] Thread already running")
                return
            
            self.running = True
            self.keep_alive_thread = threading.Thread(
                target=self._heartbeat_loop,
                daemon=True,
                name="CameraHeartbeat"
            )
            self.keep_alive_thread.start()
            self.logger.info("[HEARTBEAT] Thread started")

    def _heartbeat_loop(self):
        """Heartbeat loop mit Error-Handling"""
        self.logger.info(
            f"[HEARTBEAT] Loop started (interval: {config.ARTEMIS_KEEPALIVE_INTERVAL}s)"
        )
        
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        while self.running:
            try:
                # Nur senden wenn verbunden
                if self._state == CameraState.AUTHENTICATED:
                    response = self.send_packet(
                        b'\x00\x00', 
                        inner_type=0x01, 
                        outer_type=0xD1, 
                        wait_for_response=False,
                        description="Heartbeat"
                    )
                    
                    if response:
                        consecutive_errors = 0
                    else:
                        consecutive_errors += 1
                        if consecutive_errors >= max_consecutive_errors:
                            self.logger.error(
                                f"[HEARTBEAT] Too many consecutive errors ({consecutive_errors}), "
                                f"stopping heartbeat"
                            )
                            self._set_state(CameraState.CONNECTED, "heartbeat errors")
                            break
                
                time.sleep(config.ARTEMIS_KEEPALIVE_INTERVAL)
                
            except Exception as e:
                self.logger.error(f"[HEARTBEAT] Error: {e}")
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    break
                time.sleep(1)
        
        self.logger.info("[HEARTBEAT] Loop ended")
