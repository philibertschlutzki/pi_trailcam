import socket
import time
import logging
import struct
import threading
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

class CameraClient:
    """
    Client for cameras with the Artemis protocol (Wrapped F1... / D1...).
    Outer Header (4 Bytes): [F1] [Type] [Len_H] [Len_L]
    Inner Header (4 Bytes): [D1] [Type] [Seq_H] [Seq_L]
    """

    def __init__(self, camera_ip=None, logger=None):
        self.ip = camera_ip or config.CAM_IP
        self.port = 40611
        self.sock = None
        self.seq_num = 1
        self.running = False
        self.keep_alive_thread = None
        self.logger = logger or logging.getLogger(__name__)
        self.session_token = None
        self.sequence_bytes = None

    def set_session_credentials(self, token: str, sequence: bytes):
        """
        Set auth credentials extracted from BLE.

        Args:
            token: Base64 string, 45 characters
            sequence: 4 bytes from BLE (e.g., b'\x2b\x00\x00\x00')
        """
        if len(token) != 45:
            self.logger.warning(f"Token length {len(token)} != 45")

        self.logger.info(f"Setting session credentials: Token={token[:20]}..., Sequence={sequence.hex()}")
        self.session_token = token
        self.sequence_bytes = sequence

    def connect(self):
        self.logger.info(f"Initializing UDP Socket to {self.ip}:{self.port}...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(5.0)
            self.seq_num = 1
            return True
        except Exception as e:
            self.logger.error(f"Error creating socket: {e}")
            return False

    def close(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self.logger.info("Socket closed.")

    def _get_inner_header(self, pkt_type):
        """Creates the inner D1 header."""
        magic = 0xD1
        return struct.pack('>BBH', magic, pkt_type, self.seq_num)

    def _get_outer_header(self, inner_packet, outer_type):
        """
        Creates the outer F1 header.
        Length is the length of the entire inner packet (Header + Payload).
        """
        magic = 0xF1
        length = len(inner_packet)
        return struct.pack('>BBH', magic, outer_type, length)

    def send_packet(self, payload, inner_type=0x00, outer_type=0xD1, wait_for_response=True):
        if not self.sock:
            return None

        try:
            # 1. Build Inner Packet (D1...)
            inner_header = self._get_inner_header(inner_type)
            inner_packet = inner_header + payload

            # 2. Build Outer Packet (F1...)
            outer_header = self._get_outer_header(inner_packet, outer_type)
            final_packet = outer_header + inner_packet

            self.logger.debug(f"TX (Seq {self.seq_num}): {final_packet.hex()}")
            self.sock.sendto(final_packet, (self.ip, self.port))
            self.seq_num += 1

            if not wait_for_response:
                return True

            try:
                data, _ = self.sock.recvfrom(2048)
                self.logger.debug(f"RX: {data.hex()}")
                return data
            except socket.timeout:
                self.logger.warning(f"Timeout (Seq {self.seq_num-1})")
                return None

        except Exception as e:
            self.logger.error(f"Send Error: {e}")
            return None

    def _build_login_payload(self, variant='MYSTERY_09_01') -> bytes:
        """
        Build ARTEMIS binary login packet.
        
        Uses extracted token + sequence variant, NOT hardcoded values!
        
        Structure:
        - Protocol: "ARTEMIS\x00" (8 bytes)
        - Version: 0x02000000 (4 bytes)
        - Sequence: from variant or BLE (4 bytes)
        - Token length: 0x2d000000 (4 bytes, little-endian 45)
        - Token: extracted token + null terminator
        
        Args:
            variant: which mystery bytes variant to use (default: 'MYSTERY_09_01')
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
        
        # Sequence from variant (or BLE if variant = 'BLE_DYNAMIC')
        if variant == 'BLE_DYNAMIC' and self.sequence_bytes:
            sequence = self.sequence_bytes
        elif variant in MYSTERY_VARIANTS:
            sequence = MYSTERY_VARIANTS[variant]
        else:
            sequence = MYSTERY_VARIANTS['MYSTERY_09_01']  # Default fallback
        
        # Token length (45 bytes = 0x2d) in little-endian
        token_len_val = len(self.session_token)
        token_len_field = struct.pack('<I', token_len_val)
        
        # Token string + null terminator
        token_bytes = self.session_token.encode('ascii') + b'\x00'
        
        return artemis + version + sequence + token_len_field + token_bytes

    def login(self, variant='MYSTERY_09_01') -> bool:
        """
        Authenticate using extracted BLE token with selected variant.
        
        Args:
            variant: which mystery bytes variant to use (default: 'MYSTERY_09_01')
        
        Returns:
            True if login succeeds (camera responds)
            False if timeout or error
        """
        if not self.session_token:
            self.logger.error("No session token set!")
            return False
            
        self.logger.info("\n" + "="*70)
        self.logger.info(f"PHASE 3: UDP LOGIN (Variant: {variant})")
        self.logger.info("="*70)

        # Force sequence number to 5 as per "Real Example" / Spec suggestion
        self.seq_num = 5

        try:
            payload = self._build_login_payload(variant=variant)
            self.logger.info(f"Login Payload ({len(payload)} bytes): {payload.hex()}")
            self.logger.info(f"Mystery Bytes [12:16]: {payload[12:16].hex().upper()}")
            
            # outer_type=0xD0 for login
            response = self.send_packet(payload, inner_type=0x00, outer_type=0xD0)
            
            if response:
                self.logger.info(f"✓ LOGIN SUCCESSFUL with variant '{variant}'")
                self.start_heartbeat()
                return True
            else:
                self.logger.warning(f"✗ LOGIN FAILED with variant '{variant}'")
                return False
        except Exception as e:
            self.logger.error(f"✗ LOGIN ERROR: {e}")
            return False

    def login_all_variants(self) -> bool:
        """
        Try all mystery variants in order until one succeeds.
        Tests MYSTERY_09_01 first (from successful tcpdump).
        """
        self.logger.info("\n" + "="*70)
        self.logger.info("STARTE SYSTEMATISCHEN VARIANT-TEST")
        self.logger.info("="*70 + "\n")
        
        # Test MYSTERY_09_01 first (from tcpdump analysis)
        variant_order = ['MYSTERY_09_01', 'ORIGINAL', 'SMARTPHONE_DUMP', 
                         'MYSTERY_2B_ONLY', 'MYSTERY_2D_ONLY', 'SEQUENCE_VARIANT',
                         'BLE_DYNAMIC']
        
        for idx, variant in enumerate(variant_order, 1):
            total = len(variant_order)
            self.logger.info(f"\n--- Test {idx}/{total}: {variant} ---")
            self.logger.info(f"    Mystery Bytes: {MYSTERY_VARIANTS.get(variant, self.sequence_bytes).hex().upper()}")
            
            if self.login(variant=variant):
                self.logger.info(f"\n✓✓✓ ERFOLG MIT VARIANTE: {variant} ✓✓✓")
                return True
            
            time.sleep(1)  # Wait before next attempt
        
        self.logger.error("\n" + "="*70)
        self.logger.error("❌ ALLE VARIANTEN FEHLGESCHLAGEN")
        self.logger.error("="*70)
        return False

    def start_heartbeat(self):
        self.running = True
        self.keep_alive_thread = threading.Thread(target=self._heartbeat_loop)
        self.keep_alive_thread.daemon = True
        self.keep_alive_thread.start()

    def _heartbeat_loop(self):
        self.logger.info("Starting Heartbeat Loop (Every 2s)...")
        while self.running:
            try:
                self.send_packet(b'\x00\x00', inner_type=0x01, outer_type=0xD1, wait_for_response=False)
                time.sleep(2)
            except Exception:
                break
