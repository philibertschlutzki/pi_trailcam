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
    
    Connection Flow (Android App Verified):
    Phase 1: Initialization (0xE0 + 0xE1) - Dual-phase wake sequence
    Phase 2: Login (0xD0) - Direct authentication with BLE token
    
    REMOVED: Discovery phase (0xD1) - Camera ignores these packets!
    
    Critical Discovery from Issue #48:
    - Discovery packets (0xF1D1) timeout on all ports
    - Camera never responds to discovery
    - tcpdump shows Android app sends 0xF1D0 (LOGIN) directly after init
    - No 0xF1D1 packets in successful connection flow
    
    Conclusion: The "discovery" phase is actually the login phase.
    The camera expects LOGIN (0xD0) immediately after init.
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
        # FIX #59: Initialize Artemis sequence to 5 (start of sequence counter)
        self.artemis_seq = 5

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
            
            # FIX #59: We now start artemis_seq at 5 and increment.
            # We log the BLE sequence for reference, but we don't rely on it for the PPPP sequence counter in packet builder.
            self.logger.info(
                f"[CREDENTIALS] Token={token[:20]}..., "
                f"Sequence={sequence.hex().upper() if sequence else 'NONE'}"
            )
            # Reset Artemis Seq to 5 on new credentials
            self.artemis_seq = 5

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
            f"[SOCKET] Binding local UDP source port {port} → Destination {self.ip}:{self.port} on {bind_ip}"
        )
        try:
            self._socket_force_close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((bind_ip, port))
            timeout_val = timeout if timeout is not None else config.ARTEMIS_LOGIN_TIMEOUT
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
        
        Returns:
            bool: True if init packets were sent successfully
        """
        target_port = dest_port if dest_port else self.port
        self._set_state(CameraState.INITIALIZING, "sending UDP init packets")
        self.logger.info(f"[INIT] Sending dual-phase wakeup to {self.ip}:{target_port}...")
        
        try:
            with TimeoutContext(self.sock, config.ARTEMIS_LOGIN_TIMEOUT, self.logger):
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
                
                # FIX #48: Shorter wait (1s) before login
                # Android app shows ~1.7s delay between init and login
                self.logger.info("[INIT] Waiting 1s for camera UDP stack initialization...")
                time.sleep(1.0)
                
                return True
                
        except Exception as e:
            self.logger.warning(f"[INIT] Error during init phase: {e}")
            return True

    def _try_login_on_port(self, dest_port: int, variant: str = 'BLE_DYNAMIC') -> bool:
        """
        FIX #48: Try login directly on a specific port (no discovery).
        FIX #59: Use correct Packet Builder with Base64 token and sequence.
        
        This replaces the discovery_phase() method.
        Android app sends LOGIN (0xD0) immediately after init.
        
        Args:
            dest_port: Destination port to try
            variant: Login variant to use (ignored now, kept for signature compatibility)
            
        Returns:
            bool: True if login succeeded
        """
        self.logger.info(f"[LOGIN] Attempting direct login to port {dest_port}...")
        
        if not self.session_token:
            self.logger.error("[LOGIN] No session token available")
            return False
        
        try:
            # FIX #59: Use ArtemisPacketBuilder
            self.logger.debug(f"[LOGIN] Token input: {self.session_token}")
            self.logger.debug(f"[LOGIN] Token Base64: {base64.b64encode(self.session_token.encode()).decode()}")

            packet = ArtemisPacketBuilder.build_login_packet(
                self.session_token,
                self.artemis_seq
            )

            # Validation
            if len(packet) != 53:
                self.logger.error(f"[LOGIN] Invalid packet size: {len(packet)} (expected 53)")
                self.logger.error(f"[LOGIN] Hex dump: {packet.hex()}")
                # Don't fail immediately, try sending anyway, but log heavily

            self.logger.debug(f"[LOGIN] Packet size: {len(packet)} bytes (must be 53)")
            self.logger.debug(f"[LOGIN] Packet hex: {packet.hex()}")
            self.logger.debug(f"[LOGIN] PPPP Header: {packet[0:4].hex()}")
            self.logger.debug(f"[LOGIN] ARTEMIS Wrapper: {packet[4:8].hex()}")
            self.logger.debug(f"[LOGIN] Protocol ID: {packet[8:16]}")
            self.logger.debug(f"[LOGIN] Command: {packet[16:20].hex()}")
            self.logger.debug(f"[LOGIN] Subcommand: {packet[20]:02X} (must be 04)")
            self.logger.debug(f"[LOGIN] Parameters: {packet[21:25].hex()}")
            self.logger.debug(f"[LOGIN] Token bytes: {packet[28:53].hex()}")

            self.logger.info(f"[LOGIN] Sending to {self.ip}:{dest_port} (Seq: {self.artemis_seq})")
            
            # FIX #48: Send login burst (3 packets like Android app)
            for attempt in range(3):
                self.sock.sendto(packet, (self.ip, dest_port))
                if attempt < 2:
                    time.sleep(0.1)  # 100ms between packets
            
            self.logger.debug(f"[LOGIN] Sent burst of 3 packets to {self.ip}:{dest_port}")
            
            # Wait for response with loop to handle potential delayed LAN search responses (Issue #74)
            start_time = time.time()
            timeout = self.sock.gettimeout() or 5.0
            
            while time.time() - start_time < timeout:
                try:
                    data, addr = self.sock.recvfrom(2048)
                    duration = time.time() - start_time
                    self.logger.debug(f"[LOGIN] Received {len(data)} bytes from {addr} in {duration:.2f}s")

                    # Unwrap
                    try:
                        response = self.pppp.unwrap_pppp(data)
                    except Exception as e:
                        self.logger.warning(f"[LOGIN] Unwrappable packet received: {e}")
                        continue

                    # Check for LAN Search Response (0x41) and ignore it (Fix #74)
                    if response.get('outer_type') == 0x41:
                        self.logger.warning("[LOGIN] Ignoring delayed LAN Search Response (0x41) - clearing buffer...")
                        continue

                    self.logger.debug(f"[LOGIN] Response hex: {data.hex()}")

                    # FIX #24: Accept both 0x01 and 0x04 as valid login responses
                    if response['subcommand'] in [0x01, 0x04]:
                        self.logger.info(
                            f"[LOGIN] ✓ SUCCESS on port {dest_port} "
                            f"(Subcommand: 0x{response['subcommand']:02X})"
                        )
                        self._set_state(CameraState.AUTHENTICATED, f"port {dest_port}")
                        self.port = dest_port  # Update port for future communications

                        # Sync PPPP sequence so next packet (heartbeat) continues from login sequence
                        self.pppp.reset_sequence(self.artemis_seq)

                        return True
                    else:
                        self.logger.warning(
                            f"[LOGIN] Unexpected subcommand: 0x{response['subcommand']:02X}"
                        )
                        self.logger.debug(f"[LOGIN] Full response: {response}")
                        # Don't return False immediately, keep listening in case valid packet is behind this one
                        continue

                except socket.timeout:
                    break

            self.logger.warning(f"[LOGIN] Timeout or no valid login response on port {dest_port}")
            return False

        except socket.timeout:
            self.logger.warning(f"[LOGIN] Timeout on port {dest_port}")
            return False
        except Exception as e:
            self.logger.error(f"[LOGIN] Error on port {dest_port}: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False

    def connect_with_retries(self) -> bool:
        """
        FIX #48: Direct login flow (no discovery).
        
        Flow:
        1. Create socket
        2. Send init packets (0xE0 + 0xE1)
        3. Try login (0xD0) on multiple ports
        4. If successful, start heartbeat
        """
        self._set_state(CameraState.CONNECTING, "starting connection")
        max_retries = config.MAX_CONNECTION_RETRIES
        start_time_total = time.time()

        # FIX #48: Initialize PPPP sequence
        self.logger.info("[CONNECT] Resetting PPPP sequence to 1")
        self.pppp.reset_sequence(1)

        # FIX #59: Initialize Artemis sequence to 5
        self.artemis_seq = 5

        # Destination ports to try
        target_ports = [
            40611,    # Primary port from logs
            32100,    # CS2P2P Standard
            32108,    # Broadcast Discovery Standard
        ]

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

            # Create socket with OS-assigned port
            if not self._create_socket(0, timeout=5.0):
                self.logger.error("[CONNECT] Failed to create socket")
                time.sleep(1)
                continue

            # Get assigned port
            try:
                actual_local_ip, actual_local_port = self.sock.getsockname()
                self.active_port = actual_local_port
                self.logger.info(f"[CONNECT] Using source port: {actual_local_port}")
            except Exception as e:
                self.logger.error(f"[CONNECT] Failed to read assigned port: {e}")
                self._socket_force_close()
                continue

            # PHASE 1.5: LAN Search Broadcast (0x30)
            # Send broadcast to wake up / discover camera on port 32108
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                lan_search = self.pppp.wrap_lan_search()
                self.logger.info(f"[CONNECT] Sending LAN Search (0x30) to 32108...")
                self.sock.sendto(lan_search, ('255.255.255.255', 32108))
                self.sock.sendto(lan_search, (self.ip, 32108)) # Unicast too

                # FIX #69: Listen for response (0xF141) from camera.
                # Camera responds from 40611, confirming it is awake and on that port.
                # If we don't wait/listen, we might send Init packets too early or to wrong port.
                try:
                    # Short timeout for discovery response
                    self.sock.settimeout(2.0)
                    data, addr = self.sock.recvfrom(1024)
                    self.logger.info(f"[CONNECT] Received LAN Search response from {addr}: {data.hex()}")

                    # Update target ports if response comes from a new/different port
                    resp_ip, resp_port = addr

                    # If the camera responds, we should prioritize that port
                    if resp_port not in target_ports:
                         self.logger.info(f"[CONNECT] Adding discovered port {resp_port} to target list")
                         target_ports.insert(0, resp_port)
                    elif resp_port != target_ports[0]:
                         # Move to front
                         target_ports.remove(resp_port)
                         target_ports.insert(0, resp_port)
                         self.logger.info(f"[CONNECT] Prioritizing discovered port {resp_port}")

                except socket.timeout:
                    self.logger.debug("[CONNECT] No response to LAN Search (normal if camera asleep or on different network segment)")
                except Exception as e:
                    self.logger.warning(f"[CONNECT] Error listening for LAN Search response: {e}")
                finally:
                    # Restore default timeout
                    self.sock.settimeout(config.ARTEMIS_LOGIN_TIMEOUT)

            except Exception as e:
                self.logger.warning(f"[CONNECT] Failed to send LAN Search: {e}")

            # Send init packets to primary port
            self.logger.info(f"[INIT] Sending to port {target_ports[0]}...")
            if not self._send_init_packets(dest_port=target_ports[0]):
                self.logger.warning("[INIT] Failed to send init packets")
                self._socket_force_close()
                continue

            # FIX #48: Reset PPPP sequence after init
            self.logger.info("[FIX #48] Resetting PPPP sequence to 1 after init")
            self.pppp.reset_sequence(1)

            # Try login on each port
            login_successful = False
            for port in target_ports:
                self.logger.info(f"[CONNECT] Trying login on port {port}...")
                
                # Try with current seq
                if self._try_login_on_port(port, variant='BLE_DYNAMIC'):
                    login_successful = True
                    break
                
                # FIX #59: Increment Artemis sequence for next attempt/port
                self.artemis_seq += 1
                # Max seq check?
                if self.artemis_seq > 100:
                    self.artemis_seq = 5 # Reset if too high?

            if login_successful:
                self.logger.info(
                    f"[CONNECT] ✓ Successfully authenticated on port {self.port}"
                )
                self._set_state(CameraState.CONNECTED, f"port {self.port}")
                self.start_heartbeat()
                return True
            else:
                self.logger.warning("[CONNECT] All ports failed this attempt.")
                self._socket_force_close()

            # Backoff before retry
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
        """
        FIX #48: This method is deprecated in favor of _try_login_on_port().
        Kept for backward compatibility.
        """
        return self._try_login_on_port(self.port, variant=variant)

    def try_all_variants(self) -> bool:
        """
        FIX #48: This method is deprecated.
        Direct login flow tries BLE_DYNAMIC on all ports instead.
        """
        self.logger.warning("[LOGIN] try_all_variants() is deprecated in direct login flow")
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
                    # FIX #59: Send correct JSON payload for heartbeat
                    json_payload = json.dumps({"cmdId": 525}).encode('utf-8')
                    packet = self.pppp.wrap_heartbeat(json_payload)

                    if self.sock:
                        self.sock.sendto(packet, (self.ip, self.port))
                        self.logger.debug(f"[HEARTBEAT] Sent seq {self.pppp.get_sequence()}")
                time.sleep(config.ARTEMIS_KEEPALIVE_INTERVAL)
            except Exception as e:
                self.logger.error(f"[HEARTBEAT] Error: {e}")
                break
