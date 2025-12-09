import socket
import time
import logging
import struct
import threading
import subprocess
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
    
    FIX #25: Timing and Port Optimization (Issue #27)
    - Increased ARTEMIS_DISCOVERY_TIMEOUT from 3 to 5 seconds
    - Added CAMERA_STARTUP_DELAY (8s) before discovery attempts
    - Reordered DEVICE_PORTS with 57743 first (proven successful)
    - Extended MAX_TOTAL_CONNECTION_TIME from 60 to 90 seconds
    - Improved diagnostic logging for init phase
    
    FIX #31: Source Port Caching for Reconnect Reliability
    - Cache client source port after first successful connection
    - Reuse cached port on reconnect attempts
    - Camera maintains firewall entries per (client_ip, client_port) pair
    - Changing source port breaks session tracking

    FIX #32: Robust Reconnect Logic
    - Correctly handle source port selection even if discovery fails.
    - Prevent NoneType error when binding port on retries.
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

        # FIX #42: Check firewall on init
        check_firewall(self.logger)

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
        # FIX #42: Explicit Interface Binding
        bind_ip = '0.0.0.0'
        wlan_ip = get_wlan_ip()
        if wlan_ip:
             self.logger.info(f"[SOCKET] Binding to camera AP interface: {wlan_ip}")
             bind_ip = wlan_ip
        else:
             self.logger.warning("[SOCKET] Could not detect camera AP IP, binding to 0.0.0.0")

        self.logger.info(
            f"[SOCKET] Binding local UDP source port {port} → Destination {self.ip}:{config.CAM_PORT} on {bind_ip}"
        )
        try:
            self._socket_force_close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((bind_ip, port))
            timeout_val = timeout if timeout is not None else config.ARTEMIS_DISCOVERY_TIMEOUT
            self.sock.settimeout(timeout_val)
            self.active_port = port
            return True
        except Exception as e:
            self.logger.error(f"[SOCKET] Creation failed: {e}")
            self._socket_force_close()
            return False

    def _send_init_packets(self, dest_port: Optional[int] = None) -> bool:
        """
        FIX #24: Send initialization packets (0xE1) to wake camera UDP stack.
        FIX #25: Enhanced logging for diagnostics
        FIX #29: Send wakeup burst (5-10 packets) to "knock" on the port.
        
        These packets must be sent BEFORE discovery phase.
        TCPDump shows official app sends 2-3 init packets before discovery:
        - f1e1 0004 e100 0001
        - f1e1 0004 e100 0002
        
        Without these, camera's UDP stack remains dormant and discovery times out.
        
        Returns:
            bool: True if init packets were sent successfully
        """
        target_port = dest_port if dest_port else self.port
        self._set_state(CameraState.INITIALIZING, "sending UDP init packets")
        self.logger.info(f"[INIT] Sending wakeup burst to {self.ip}:{target_port}...")
        
        try:
            with TimeoutContext(self.sock, config.ARTEMIS_DISCOVERY_TIMEOUT, self.logger):
                # FIX #29: Increased burst size to 5 to ensure wakeup
                # FIX #40-3: Reduced from 5 to 3 packets to match Android app behavior
                for i in range(3):
                    init_packet = self.pppp.wrap_init()
                    self.sock.sendto(init_packet, (self.ip, target_port))
                    self.logger.debug(f"[INIT] Sent packet {i+1}/3: {init_packet.hex()}")
                    time.sleep(0.05)  # 50ms delay between packets
                
                self.logger.info("[INIT] ✓ Wakeup burst sent successfully")
                return True
                
        except Exception as e:
            self.logger.warning(f"[INIT] Error during init phase: {e}")
            # Don't fail connection on init errors - camera might already be awake
            return True

    def discovery_phase(self, dest_port: Optional[int] = None) -> bool:
        """
        Sends the PPPP wrapped discovery packet.
        
        FIX #22: Do NOT reset pppp_seq here!
        PPPP sequence is per-session, not per-attempt.
        Resetting caused all discovery packets to have Seq=0x0001
        which the camera rejects as duplicate/corrupted.
        
        FIX #23: Use BLE-provided artemis_seq instead of hardcoded value.
        
        FIX #24: Must be called AFTER _send_init_packets().
        
        FIX #25: Enhanced diagnostics logging
        """
        self._set_state(CameraState.DISCOVERING, "starting discovery")
        self.logger.info("[DISCOVERY] Sending PPPP Discovery...")
        
        # DEBUG: Log current PPPP Seq before wrapping
        current_pppp_seq = self.pppp.get_sequence()
        self.logger.debug(f"[DISCOVERY DEBUG] PPPP Seq before wrap: 0x{current_pppp_seq:04X}")
        self.logger.debug(f"[DISCOVERY DEBUG] Artemis Seq to use: 0x{self.artemis_seq:04X}")
        
        # Create wrapped discovery packet
        packet = self.pppp.wrap_discovery(self.artemis_seq)
        target_port = dest_port if dest_port else self.port

        # DEBUG: Log PPPP Seq after wrapping
        new_pppp_seq = self.pppp.get_sequence()
        self.logger.debug(f"[DISCOVERY DEBUG] PPPP Seq after wrap: 0x{new_pppp_seq:04X}")
        self.logger.info(f"[DISCOVERY] Sending to {self.ip}:{target_port} - Packet: {packet.hex()}")

        # Increment Artemis sequence for next packet
        self.artemis_seq += 1
        
        start_time = time.time()
        
        try:
            # FIX #42: Increase timeout to 10s
            timeout_val = 10.0

            with TimeoutContext(self.sock, timeout_val, self.logger):
                # FIX #42: Burst of 3 packets with delays
                for attempt in range(3):
                    self.sock.sendto(packet, (self.ip, target_port))
                    if attempt < 2:
                        time.sleep(0.1)  # 100ms between packets
                
                self.logger.debug(f"[DISCOVERY] Sent burst of 3 packets to {self.ip}:{target_port}")

                # Expect response
                # FIX #42: Raw Packet Debugging
                data, addr = self.sock.recvfrom(4096)
                duration = time.time() - start_time
                
                self.logger.debug(f"[RAW] Received {len(data)} bytes from {addr}")
                self.logger.debug(f"[RAW] Hex: {data.hex()}")
                if len(data) >= 4:
                    self.logger.debug(f"[PARSE] Magic: 0x{data[0]:02x}, Type: 0x{data[1]:02x}")

                # Unwrap and validate
                try:
                    response = self.pppp.unwrap_pppp(data)
                    if response['subcommand'] == 0x01: # Discovery ACK
                        self.logger.info(f"[DISCOVERY] ✓ Response: {data.hex()} from {addr} in {duration:.2f}s")
                        self._set_state(CameraState.DISCOVERED, f"on source port {self.active_port}")
                        return True
                    else:
                        self.logger.warning(f"[DISCOVERY] Unexpected subcommand: 0x{response['subcommand']:02X}")
                        self.logger.debug(f"[DISCOVERY] Full parsed response: {response}")
                except ValueError as ve:
                    self.logger.error(f"[DISCOVERY] Invalid response: {ve}")

                return False
                
        except socket.timeout:
            duration = time.time() - start_time
            self.logger.warning(f"[DISCOVERY] ✗ Timeout after {duration:.2f}s (Port {self.active_port})")
            return False
        except Exception as e:
            self.logger.error(f"[DISCOVERY] Error: {e}")
            return False

    def discover_device(self) -> bool:
        """
        FIX #31: Discovery with dynamic source port handling.
        
        This method wraps the internal discovery implementation.
        For first connection: port=0 (OS assigns)
        For reconnect: port=cached (reuse same port)
        
        Returns:
            bool: True if device discovered and port identified.
        """
        return self._discover_device_internal(source_port=0)

    def _discover_device_internal(self, source_port: int = 0) -> bool:
        """
        FIX #35: Send init burst ONCE to primary port, not per destination port.
        
        Root Cause: Repeated init bursts (5 per port × 6 ports) caused PPPP
        sequence overflow (6, 12, 18, 24, 30, ...) before first discovery completes.
        
        Solution: Match Android app behavior - single init burst to primary port 40611,
        then scan all ports with discovery only (no additional init per port).
        
        Evidence from logs:
        - Android Success (v2): Single init, immediate discovery success
        - Python Failure (#35): 30 init packets, PPPP seq=6,12,18,... discovery fails
        """
        self._set_state(CameraState.DISCOVERING, "scanning ports")

        # Destination ports to try on camera
        target_ports = [
            40611,    # From logs - THIS IS THE SERVER LISTENING PORT
            32100,    # CS2P2P Standard
            32108,    # Broadcast Discovery Standard
            10000,
            80,
            57743     # iOS success port
        ]

        # Create socket with specified source port
        if not self._create_socket(source_port, timeout=2.0):
            self.logger.error(f"[DISCOVERY] Failed to bind source port {source_port}")
            return False

        # FIX #31: After binding, read the actual assigned local port
        if source_port == 0:
            try:
                actual_local_ip, actual_local_port = self.sock.getsockname()
                self.active_port = actual_local_port
                self.logger.info(f"[DISCOVERY] OS assigned local source port: {actual_local_port}")
            except Exception as e:
                self.logger.error(f"[DISCOVERY] Failed to read assigned port: {e}")
                return False
        else:
            # Port was explicitly specified, use it
            self.active_port = source_port
            self.logger.info(f"[DISCOVERY] Reusing cached source port: {source_port}")

        # FIX #35: Send init burst ONCE to primary port BEFORE scanning all ports
        # This matches Android app behavior and keeps PPPP sequence low
        self.logger.info(f"[INIT] Sending wakeup burst to primary port {target_ports[0]} (ONCE for all ports)...")
        self._send_init_packets(dest_port=target_ports[0])

        # === FIX #40-2: RESET PPPP SEQUENCE AFTER INIT BURST ===
        # Problem: Init burst (5 packets) increases PPPP seq to 5
        # Discovery then starts at seq=6, which camera may reject
        # Solution: Reset to seq=1 AFTER init, BEFORE discovery
        # This ensures Discovery packet has seq=1 (like Android app)
        self.logger.info("[FIX #40] Resetting PPPP sequence to 1 after init burst")
        self.pppp.reset_sequence(1)
        # === END FIX #40-2 ===

        # Brief pause to allow camera UDP stack initialization
        time.sleep(0.5)

        self.logger.info(f"[DISCOVERY] Scanning {len(target_ports)} destination ports...")

        for port in target_ports:
            self.logger.info(f"[DISCOVERY] Trying destination port {port}...")

            # FIX #35: Discovery ONLY - no additional init burst per port
            # PPPP sequence stays low (1, 2, 3, ... instead of 6, 12, 18, ...)
            if self.discovery_phase(dest_port=port):
                self.logger.info(
                    f"[DISCOVERY] ✓ FOUND CAMERA on destination port {port} "
                    f"with source port {self.active_port}"
                )
                self.port = port
                return True

        return False

    def connect_with_retries(self) -> bool:
        """
        FIX #31: Connection with source port caching.
        
        CRITICAL: The camera maintains firewall entries based on (client_ip, client_port).
        If we change the source port on reconnect, the camera will drop packets.
        
        Solution:
        1. First attempt: Let OS assign source port (port=0)
        2. Cache this port
        3. On reconnects: Explicitly bind to cached port (not port=0)
        
        This ensures the camera always receives packets from the same source address.
        """
        self._set_state(CameraState.CONNECTING, "starting retry loop")
        max_retries = config.MAX_CONNECTION_RETRIES
        start_time_total = time.time()

        # FIX #22: Initialize PPPP sequence once for the entire connection session
        self.logger.info("[CONNECT] Resetting PPPP sequence to 1")
        self.pppp.reset_sequence(1)

        # FIX #31: Cache the source port across reconnect attempts
        cached_source_port = None
        is_first_attempt = True

        for attempt in range(max_retries):
            elapsed = time.time() - start_time_total
            if elapsed > config.MAX_TOTAL_CONNECTION_TIME:
                self._set_state(CameraState.CONNECTION_FAILED, "total timeout")
                self.logger.error(
                    f"[CONNECT] Total connection time exceeded "
                    f"({elapsed:.1f}s > {config.MAX_TOTAL_CONNECTION_TIME}s)"
                )
                return False

            self.logger.info(f"[CONNECT] Attempt {attempt + 1}/{max_retries}")

            # FIX #31: Decide which source port to use
            if is_first_attempt:
                # First attempt: Let OS assign port
                source_port = 0
                self.logger.debug("[CONNECT] First attempt - requesting OS-assigned source port")
            else:
                # Reconnect attempts: Reuse the cached port
                if cached_source_port:
                    source_port = cached_source_port
                    self.logger.debug(
                        f"[CONNECT] Reconnect attempt - reusing cached source port {source_port}"
                    )
                else:
                    # FIX #32: Fallback to 0 if no cached port available (prevent NoneType error)
                    source_port = 0
                    self.logger.warning(
                        "[CONNECT] Reconnect attempt - no cached source port, requesting OS-assigned"
                    )

            # Try to discover device with this source port
            if self._discover_device_internal(source_port=source_port):
                # Success! Cache the port for future reconnects
                cached_source_port = self.active_port
                self.logger.info(
                    f"[CONNECT] ✓ Successfully connected on source port {self.active_port}"
                )
                self._set_state(CameraState.CONNECTED, f"dest port {self.port}")
                self.sock.settimeout(config.ARTEMIS_LOGIN_TIMEOUT)
                is_first_attempt = False
                return True
            else:
                self.logger.warning("[CONNECT] Discovery scan failed this attempt.")

                # FIX #37: Do NOT cache the source port if discovery failed!
                # If we cache a failed port, we just retry with the same bad port/state.
                # Let the OS assign a new port on the next attempt.
                # (Reverts part of FIX #32 logic which was causing Issue #37)

                self._socket_force_close()
                is_first_attempt = False

            backoff = config.RETRY_BACKOFF_SEQUENCE[
                min(attempt, len(config.RETRY_BACKOFF_SEQUENCE) - 1)
            ]
            
            if cached_source_port:
                self.logger.info(
                    f"[CONNECT] Waiting {backoff}s before retry... "
                    f"(will reuse source port {cached_source_port})"
                )
            else:
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
