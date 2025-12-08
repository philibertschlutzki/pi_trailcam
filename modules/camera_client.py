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
    'BLE_DYNAMIC': None,  # Special: Use sequence_bytes directly
}

class CameraState(Enum):
    DISCONNECTED = auto()
    INITIALIZING = auto()  # NEW: For init packet phase
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
    
    Connection Flow (PROTOCOL_ANALYSIS Section 4):
    Phase 1: Initialization (0xE1) - Wakes up the camera UDP stack.
    Phase 2: Discovery (0xD1) - Verifies device presence and establishes path.
    Phase 3: Login (0xD0) - Authenticates using token and sequence from BLE.

    FIX #21: Discovery Packet Format
    Official App uses a minimal F1 E0 00 00 packet for discovery.
    
    FIX #22: PPPP Sequence Management
    PPPP sequence number is per-session, not per-attempt.
    
    FIX #23: Artemis Sequence from BLE
    Use BLE-provided sequence bytes for Discovery/Login instead of hardcoded 0x001B.
    
    FIX #24: UDP Login Handshake Optimization
    - Send initialization packets (0xE1) before discovery to wake UDP stack
    - Use correct login packet type (0xD0 in pppp_wrapper)
    - Include full Artemis login payload with proper structure
    - Accept both 0x01 and 0x04 as valid login responses
    """

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

        # PPPP Integration
        self.pppp = PPPPWrapper(logger=self.logger)
        self.artemis_seq = 0x001B  # Fallback if BLE sequence not available

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

        Token Format Support:
        The camera supports both JSON and raw binary formats for the token.
        Parsing logic is handled in `ble_token_listener.py`.
        This method receives the extracted token string ready for use.
        
        FIX #23: Parse sequence bytes and set artemis_seq for Discovery/Login.
        The sequence is typically 4 bytes in little-endian format.
        """
        with self._lock:
            self.session_token = token
            self.sequence_bytes = sequence if use_ble_dynamic else None
            self.token_timestamp = time.time()
            
            # FIX #23: Parse sequence bytes and set artemis_seq
            if sequence and len(sequence) >= 4:
                # Sequence is 4 bytes, little-endian
                # e.g., 48 00 00 00 -> 0x00000048 = 72 decimal
                self.artemis_seq = struct.unpack('<I', sequence[:4])[0]
                self.logger.info(
                    f"[CREDENTIALS] Token={token[:20]}..., "
                    f"Sequence={sequence.hex().upper()}, "
                    f"Artemis Seq=0x{self.artemis_seq:04X} ({self.artemis_seq})"
                )
            else:
                self.logger.warning(
                    f"[CREDENTIALS] Token={token[:20]}..., "
                    f"Sequence={sequence.hex().upper() if sequence else 'NONE'}, "
                    f"Using fallback Artemis Seq=0x{self.artemis_seq:04X}"
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
        """
        Creates and binds the UDP socket.

        Why Source Port Binding?
        The camera uses a firewall mechanism that only responds to packets
        from specific source ports (port-knocking pattern).
        See FIXES_ISSUE_20.md Section "Why Source Port Binding Works" for details.

        The list of allowed source ports is defined in `config.DEVICE_PORTS`.
        """
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
            self.active_port = port
            return True
        except Exception as e:
            self.logger.error(f"[SOCKET] Creation failed: {e}")
            self._socket_force_close()
            return False

    def _send_init_packets(self) -> bool:
        """
        FIX #24: Send initialization packets (0xE1) to wake camera UDP stack.
        
        These packets must be sent BEFORE discovery phase.
        TCPDump shows official app sends 2-3 init packets before discovery:
        - f1e1 0004 e100 0001
        - f1e1 0004 e100 0002
        
        Without these, camera's UDP stack remains dormant and discovery times out.
        
        Returns:
            bool: True if init packets were sent successfully
        """
        self._set_state(CameraState.INITIALIZING, "sending UDP init packets")
        self.logger.info("[INIT] Sending initialization packets to wake camera UDP stack...")
        
        try:
            with TimeoutContext(self.sock, config.ARTEMIS_DISCOVERY_TIMEOUT, self.logger):
                # Send 2 init packets (as seen in TCPDump)
                for i in range(2):
                    init_packet = self.pppp.wrap_init()
                    self.sock.sendto(init_packet, (self.ip, self.port))
                    self.logger.debug(f"[INIT] Sent packet {i+1}: {init_packet.hex()}")
                    time.sleep(0.05)  # 50ms delay between packets
                
                self.logger.info("[INIT] ✓ Initialization packets sent successfully")
                return True
                
        except Exception as e:
            self.logger.warning(f"[INIT] Error during init phase: {e}")
            # Don't fail connection on init errors - camera might already be awake
            return True

    def discovery_phase(self) -> bool:
        """
        Sends the PPPP wrapped discovery packet.
        
        FIX #22: Do NOT reset pppp_seq here!
        PPPP sequence is per-session, not per-attempt.
        Resetting caused all discovery packets to have Seq=0x0001
        which the camera rejects as duplicate/corrupted.
        
        FIX #23: Use BLE-provided artemis_seq instead of hardcoded value.
        
        FIX #24: Must be called AFTER _send_init_packets().
        """
        self._set_state(CameraState.DISCOVERING, "starting discovery")
        self.logger.info("[DISCOVERY] Sending PPPP Discovery...")
        
        # DEBUG: Log current PPPP Seq before wrapping
        current_pppp_seq = self.pppp.get_sequence()
        self.logger.debug(f"[DISCOVERY DEBUG] PPPP Seq before wrap: 0x{current_pppp_seq:04X}")
        self.logger.debug(f"[DISCOVERY DEBUG] Artemis Seq to use: 0x{self.artemis_seq:04X}")
        
        # Create wrapped discovery packet
        packet = self.pppp.wrap_discovery(self.artemis_seq)
        
        # DEBUG: Log PPPP Seq after wrapping
        new_pppp_seq = self.pppp.get_sequence()
        self.logger.debug(f"[DISCOVERY DEBUG] PPPP Seq after wrap: 0x{new_pppp_seq:04X}")
        self.logger.info(f"[DISCOVERY] Sent packet: {packet.hex()}")

        # Increment Artemis sequence for next packet
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
        """
        FIX #24: Connection flow with init packets:
        1. Reset PPPP sequence (once per session)
        2. For each port:
           a. Create socket
           b. Send init packets (NEW!)
           c. Send discovery
           d. If success, return
        """
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
                    # FIX #24: Send initialization packets BEFORE discovery
                    self._send_init_packets()
                    
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
        """
        Build Artemis login payload.
        
        FIX #24: Ensure complete structure:
        - "ARTEMIS\x00" (8 bytes)
        - Version (4 bytes, little-endian)
        - Sequence from BLE or variant (4 bytes)
        - Token length (4 bytes, little-endian)
        - Token string + null terminator
        
        TCPDump structure:
        4152 5445 4d49 5300 = "ARTEMIS\x00"
        0200 0000           = Version 2
        0200 0100           = Sequence (from BLE)
        1900 0000           = Token length (25 bytes)
        4d7a 6c42...        = Token data
        """
        if not self.session_token:
            raise ValueError("No token set")
        
        artemis = b'ARTEMIS\x00'
        version = b'\x02\x00\x00\x00'
        
        # Use BLE sequence if available and variant is BLE_DYNAMIC
        if variant == 'BLE_DYNAMIC' and self.sequence_bytes:
            # Use first 4 bytes of BLE sequence
            sequence = self.sequence_bytes[:4] if len(self.sequence_bytes) >= 4 else b'\x00\x00\x00\x00'
            self.logger.debug(f"[LOGIN PAYLOAD] Using BLE sequence: {sequence.hex().upper()}")
        else:
            sequence = MYSTERY_VARIANTS.get(variant, MYSTERY_VARIANTS['MYSTERY_09_01'])
            self.logger.debug(f"[LOGIN PAYLOAD] Using variant '{variant}': {sequence.hex().upper()}")
        
        token_len = struct.pack('<I', len(self.session_token))
        token_bytes = self.session_token.encode('ascii') + b'\x00'
        
        payload = artemis + version + sequence + token_len + token_bytes
        self.logger.debug(f"[LOGIN PAYLOAD] Total length: {len(payload)} bytes")
        
        return payload

    def login(self, variant: str = 'MYSTERY_09_01') -> bool:
        """
        FIX #24: Login with improved error handling and logging.
        
        Changes:
        - Log full packet hex for debugging
        - Accept both 0x01 and 0x04 as valid responses
        - Better error messages with traceback
        - Verify packet starts with f1d0 (not f1d1)
        """
        if not self.session_token:
            self.logger.error("[LOGIN] No session token available")
            return False
        
        try:
            # Build Artemis payload
            artemis_payload = self._build_login_payload(variant)

            # Wrap in PPPP (FIX #24: Now uses 0xD0 outer type)
            packet = self.pppp.wrap_login(artemis_payload)

            # Verify packet starts with correct bytes
            if packet[0:2] != b'\xf1\xd0':
                self.logger.warning(
                    f"[LOGIN] Packet should start with f1d0 but starts with {packet[0:2].hex()}"
                )

            self.logger.info(f"[LOGIN] Sending Login (Variant: {variant})...")
            self.logger.debug(f"[LOGIN] Full packet hex: {packet.hex()}")
            self.logger.debug(f"[LOGIN] Packet length: {len(packet)} bytes")
            
            self.sock.sendto(packet, (self.ip, self.port))
            
            # Receive response
            data, addr = self.sock.recvfrom(2048)
            self.logger.debug(f"[LOGIN] Received response: {data.hex()}")

            # Unwrap
            response = self.pppp.unwrap_pppp(data)
            
            # FIX #24: Accept both 0x01 and 0x04 as valid login responses
            # 0x04 = Official login ACK
            # 0x01 = Alternative ACK seen in some camera models
            if response['subcommand'] in [0x01, 0x04]:
                self.logger.info(
                    f"[LOGIN] ✓ SUCCESS (Subcommand: 0x{response['subcommand']:02X})"
                )
                self._set_state(CameraState.AUTHENTICATED, f"variant {variant}")
                self.start_heartbeat()
                return True
            else:
                self.logger.warning(
                    f"[LOGIN] Failed. Unexpected subcommand: 0x{response['subcommand']:02X}"
                )
                self.logger.debug(f"[LOGIN] Full response: {response}")
                return False

        except socket.timeout:
            self.logger.error("[LOGIN] Timeout - camera did not respond")
            return False
        except Exception as e:
            self.logger.error(f"[LOGIN] Error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def try_all_variants(self) -> bool:
        """
        Try all login variants in sequence.
        
        FIX #24: Try BLE_DYNAMIC first if sequence_bytes available.
        """
        # Try BLE_DYNAMIC first if we have BLE sequence
        if self.sequence_bytes:
            self.logger.info("[LOGIN] Trying BLE_DYNAMIC variant first...")
            if self.login(variant='BLE_DYNAMIC'):
                return True
        
        # Try other variants
        for variant_name in MYSTERY_VARIANTS.keys():
            if variant_name == 'BLE_DYNAMIC':
                continue  # Already tried
            
            self.logger.info(f"[LOGIN] Trying variant: {variant_name}")
            if self.login(variant=variant_name):
                return True
        
        return False

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
                    packet = self.pppp.wrap_heartbeat(self.artemis_seq)
                    if self.sock:
                        self.sock.sendto(packet, (self.ip, self.port))
                        self.logger.debug(f"[HEARTBEAT] Sent seq {self.artemis_seq}")
                time.sleep(config.ARTEMIS_KEEPALIVE_INTERVAL)
            except Exception as e:
                self.logger.error(f"[HEARTBEAT] Error: {e}")
                break
