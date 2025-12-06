import socket
import time
import logging
import struct
import threading
import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CameraClient:
    """
    Client für Kameras mit dem Artemis-Protokoll (Wrapped F1... / D1...).
    Outer Header (4 Bytes): [F1] [Type] [Len_H] [Len_L]
    Inner Header (4 Bytes): [D1] [Type] [Seq_H] [Seq_L]
    """

    def __init__(self):
        self.ip = config.CAM_IP
        self.port = 40611
        self.sock = None
        self.seq_num = 1
        self.running = False
        self.keep_alive_thread = None

    def connect(self):
        logger.info(f"Initialisiere UDP Socket zu {self.ip}:{self.port}...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(5.0) # Etwas mehr Timeout für den ersten Connect
            self.seq_num = 1
            return True
        except Exception as e:
            logger.error(f"Fehler beim Erstellen des Sockets: {e}")
            return False

    def close(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        logger.info("Socket geschlossen.")

    def _get_inner_header(self, pkt_type):
        """Erstellt den inneren D1 Header."""
        magic = 0xD1
        return struct.pack('>BBH', magic, pkt_type, self.seq_num)

    def _get_outer_header(self, inner_packet, outer_type):
        """
        Erstellt den äußeren F1 Header.
        Länge ist die Länge des gesamten inneren Pakets (Header + Payload).
        """
        magic = 0xF1
        length = len(inner_packet)
        return struct.pack('>BBH', magic, outer_type, length)

    def send_packet(self, payload, inner_type=0x00, outer_type=0xD1, wait_for_response=True):
        if not self.sock:
            return None

        try:
            # 1. Inneres Paket bauen (D1...)
            inner_header = self._get_inner_header(inner_type)
            inner_packet = inner_header + payload

            # 2. Äußeres Paket bauen (F1...)
            # Login nutzt meist outer_type 0xD0, Daten/Heartbeat 0xD1
            outer_header = self._get_outer_header(inner_packet, outer_type)
            final_packet = outer_header + inner_packet

            # logger.debug(f"TX (Seq {self.seq_num}): {final_packet.hex()}")
            self.sock.sendto(final_packet, (self.ip, self.port))
            self.seq_num += 1

            if not wait_for_response:
                return True

            try:
                data, _ = self.sock.recvfrom(2048)
                # logger.debug(f"RX: {data.hex()}")
                return data
            except socket.timeout:
                logger.warning(f"Timeout (Seq {self.seq_num-1})")
                return None

        except Exception as e:
            logger.error(f"Send Error: {e}")
            return None

    def login(self):
        logger.info("Sende Login-Handshake (Replay Attack)...")
        
        # Payload rekonstruiert aus tcpdump_1800_connect.log
        # String: ARTEMIS\0
        part1 = b'ARTEMIS\x00'
        # Versionen / Flags (02 00 00 00 02 00 01 00)
        part2 = b'\x02\x00\x00\x00\x02\x00\x01\x00'
        # String Length (25 bytes)
        part3 = b'\x19\x00\x00\x00'
        # Auth Token / Key (Base64 String + Null byte)
        # "MzlB36X/IVo8ZzI5rG9j1w=="
        part4 = b'MzlB36X/IVo8ZzI5rG9j1w==\x00'
        
        payload = part1 + part2 + part3 + part4
        
        # Für Login nutzt die App im Dump den Outer Type 0xD0
        for attempt in range(3):
            logger.info(f"Login Versuch {attempt+1}...")
            response = self.send_packet(payload, inner_type=0x00, outer_type=0xD0)
            
            if response:
                logger.info(f"Login OK! Antwort erhalten: {response.hex()}")
                self.start_heartbeat()
                return True
            time.sleep(1)
        
        logger.error("Login gescheitert.")
        return False

    def start_heartbeat(self):
        self.running = True
        self.keep_alive_thread = threading.Thread(target=self._heartbeat_loop)
        self.keep_alive_thread.daemon = True
        self.keep_alive_thread.start()

    def _heartbeat_loop(self):
        logger.info("Starte Heartbeat Loop (Alle 2s)...")
        while self.running:
            try:
                # Einfacher Keep-Alive, oft leerer Payload oder '00'
                # App sendet oft Pakete mit Type 1
                self.send_packet(b'\x00\x00', inner_type=0x01, outer_type=0xD1, wait_for_response=False)
                time.sleep(2)
            except Exception:
                break
