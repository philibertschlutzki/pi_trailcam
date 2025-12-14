import socket
import time
import logging
import struct
import threading
import subprocess
from enum import Enum, auto
from typing import Optional, Tuple
import config
from modules.protocol.pppp import PPPPProtocol

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
    FIX #44: UDP Client with corrected initialization sequence.
    
    Connection Flow:
    Phase 1: Initialization (0xE0 + 0xE1) - Dual-phase wake sequence
    Phase 2: Discovery (0xD1) - Device presence verification
    Phase 3: Login (0xD0) - Authentication with BLE token
    
    Critical Changes:
    - Init now sends TWO packets: 0xF1E0 then 0xF1E1
    - Reduced from 5-packet burst to 2-packet sequence
    - Matches Android app behavior from tcpdump analysis
    - Prevents PPPP sequence overflow before discovery
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
        self.pppp = PPPPProtocol(logger=self.logger)
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
        FIX #44: Send dual-phase initialization packets (0xE0 + 0xE1).
        
        From tcpdump_1800_connect.log:
        17:55:23.927: 0xF1E0 0000 (first init)
        17:55:23.928: 0xF1E1 0000 (second init)
        
        Critical changes:
        - Reduced from 5-packet burst to 2-packet sequence
        - Each packet type sent only once
        - Matches Android app behavior exactly
        - Prevents PPPP sequence overflow
        
        Returns:
            bool: True if init packets were sent successfully
        """
        target_port = dest_port if dest_port else self.port
        self._set_state(CameraState.INITIALIZING, "sending UDP init packets")
        self.logger.info(f"[INIT] Sending dual-phase wakeup to {self.ip}:{target_port}...")
        
        try:
            with TimeoutContext(self.sock, config.ARTEMIS_DISCOVERY_TIMEOUT, self.logger):
                # Phase 1: 0xF1E0 packet
                init_ping = self.pppp.wrap_init_ping()
                self.sock.sendto(init_ping, (self.ip, target_port))
                self.logger.debug(f"[INIT] Sent 0xE0 packet: {init_ping.hex()}")
                time.sleep(0.05)  # 50ms delay
                
                # Phase 2: 0xF1E1 packet
                init_secondary = self.pppp.wrap_init_secondary()
                self.sock.sendto(init_secondary, (self.ip, target_port))
                self.logger.debug(f"[INIT] Sent 0xE1 packet: {init_secondary.hex()}")
                
                self.logger.info("[INIT] ✓ Dual-phase wakeup sent successfully")
                
                # FIX #44: Wait 2 seconds for UDP stack initialization
                # Android app shows similar delay before discovery
                self.logger.info("[INIT] Waiting 2s for camera UDP stack initialization...")
                time.sleep(2.0)
                
                return True
                
        except Exception as e:
            self.logger.warning(f"[INIT] Error during init phase: {e}")
            # Don't fail connection on init errors - camera might already be awake
            return True

    def discovery_phase(self, dest_port: Optional[int] = None) -> bool:
        """
        Sends the PPPP wrapped discovery packet (0xF1D1).
        
        FIX #44: Must be called AFTER _send_init_packets().
        PPPP sequence should be 1 at this point (after init reset).
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
        """
        return self._discover_device_internal(source_port=0)

    def _discover_device_internal(self, source_port: int = 0) -> bool:
        """
        FIX #44: Single init burst to primary port, then scan all ports with discovery.
        
        Root Cause: Repeated init bursts caused PPPP sequence overflow.
        Solution: Match Android app - single init burst, then discovery scan.
        """
        self._set_state(CameraState.DISCOVERING, "scanning ports")

        # Destination ports to try on camera
        target_ports = [
            40611,    # Primary port from logs
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
            self.active_port = source_port
            self.logger.info(f"[DISCOVERY] Reusing cached source port: {source_port}")

        # FIX #44: Send init burst ONCE to primary port BEFORE scanning all ports
        self.logger.info(f"[INIT] Sending wakeup to primary port {target_ports[0]} (ONCE for all ports)...")
        self._send_init_packets(dest_port=target_ports[0])

        # FIX #44: RESET PPPP SEQUENCE AFTER INIT BURST
        # Ensures Discovery packet has seq=1 (like Android app)
        self.logger.info("[FIX #44] Resetting PPPP sequence to 1 after init burst")
        self.pppp.reset_sequence(1)

        self.logger.info(f"[DISCOVERY] Scanning {len(target_ports)} destination ports...")

        for port in target_ports:
            self.logger.info(f"[DISCOVERY] Trying destination port {port}...")

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
                source_port = 0
                self.logger.debug("[CONNECT] First attempt - requesting OS-assigned source port")
            else:
                if cached_source_port:
                    source_port = cached_source_port
                    self.logger.debug(
                        f"[CONNECT] Reconnect attempt - reusing cached source port {source_port}"
                    )
                else:
                    source_port = 0
                    self.logger.warning(
                        "[CONNECT] Reconnect attempt - no cached source port, requesting OS-assigned"
                    )

            # Try to discover device with this source port
            if self._discover_device_internal(source_port=source_port):
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
        """
        if not self.session_token:
            raise ValueError("No token set")
        
        artemis = b'ARTEMIS\x00'
        version = b'\x02\x00\x00\x00'
        
        # Use BLE sequence if available and variant is BLE_DYNAMIC
        if variant == 'BLE_DYNAMIC' and self.sequence_bytes:
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
        FIX #44: Uses 0xF1D0 wrapper (not 0xF1D1).
        """
        if not self.session_token:
            self.logger.error("[LOGIN] No session token available")
            return False
        
        try:
            # Build Artemis payload
            artemis_payload = self._build_login_payload(variant)

            # Wrap in PPPP (FIX #44: Now uses 0xD0 outer type)
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
