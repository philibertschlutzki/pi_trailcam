import socket
import json
import time
import logging
import struct
import config

logger = logging.getLogger(__name__)

class CameraClient:
    """
    Handles UDP Socket communication with the KJK230 Camera.
    Protocol: Proprietary Binary Header (79 bytes) + JSON Payload.
    """

    def __init__(self):
        self.ip = config.CAM_IP
        self.port = config.CAM_PORT
        self.sock = None
        self.token = 0 # Default token is 0

    def connect(self):
        """
        Initializes the UDP socket.
        Note: UDP is connectionless, but we create the socket object here.
        """
        logger.info(f"Initializing UDP Socket for {self.ip}:{self.port}...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(3.0) # 3 second timeout for responses
            return True
        except Exception as e:
            logger.error(f"Failed to create UDP socket: {e}")
            self.sock = None
            return False

    def close(self):
        """Closes the UDP socket."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        logger.info("UDP Socket closed.")

    def _get_header(self):
        """
        Constructs the 79-byte binary header required by the protocol.

        Structure:
        0-3:   EF AA 55 AA (Magic)
        4-7:   00 00 00 00
        8-11:  00 00 00 01 (Packet Type?)
        12-78: 00 ... (Padding)
        """
        # < = Little Endian, I = Unsigned Int (4 bytes)
        # However, many proprietary protocols use Big Endian (>) for networks.
        # Given "0xEF 0xAA 0x55 0xAA" and standard hex representation usually implies byte order in documentation.
        # Let's assume standard Network Byte Order (Big Endian) unless typically specified otherwise,
        # BUT RE findings often list bytes as seen in hex dump (order preserved).
        # We will build it byte by byte or using struct.

        magic = b'\xEF\xAA\x55\xAA'
        zeros = b'\x00\x00\x00\x00'
        pkt_type = b'\x00\x00\x00\x01'
        padding = b'\x00' * (79 - 12) # 79 total size - 12 bytes used

        return magic + zeros + pkt_type + padding

    def send_command(self, cmd_dict):
        """
        Wraps the JSON command in the header and sends via UDP.
        Waits for and parses the JSON response.

        Args:
            cmd_dict (dict): The command to send.

        Returns:
            dict: The JSON response parsed as a dictionary, or None if failure.
        """
        if not self.sock:
            logger.error("Cannot send command: Socket not initialized.")
            return None

        # Inject Token if not present
        if "token" not in cmd_dict:
            cmd_dict["token"] = self.token

        try:
            # 1. Prepare Payload
            json_str = json.dumps(cmd_dict)
            json_bytes = json_str.encode('utf-8')

            header = self._get_header()
            packet = header + json_bytes

            # 2. Send
            # logger.debug(f"Sending (CmdId: {cmd_dict.get('cmdId')}): {json_str}")
            self.sock.sendto(packet, (self.ip, self.port))

            # 3. Receive
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                # Some commands (like Heartbeat) might not always get a response or it might be lost
                if cmd_dict.get('cmdId') == 525:
                    logger.debug("Heartbeat sent (no response or timed out).")
                else:
                    logger.warning(f"Timeout waiting for response to CmdId {cmd_dict.get('cmdId')}")
                return None

            # 4. Parse Response
            # The response likely has the same 79-byte header. We skip it.
            if len(data) > 79:
                response_payload = data[79:]
                response_str = response_payload.decode('utf-8', errors='ignore').strip()
                # Remove any null terminators if present
                response_str = response_str.rstrip('\x00')

                # logger.debug(f"Received raw: {response_str}")

                if not response_str:
                    return None

                return json.loads(response_str)
            else:
                logger.warning(f"Received short packet ({len(data)} bytes). Expected > 79.")
                return None

        except Exception as e:
            logger.error(f"Error during send_command: {e}")
            return None

    def login(self):
        """
        Performs the login handshake (cmdId: 0).
        """
        current_ts = int(time.time())
        login_cmd = {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "needAudio": 0,
            "utcTime": current_ts,
            "supportHeartBeat": True
        }

        logger.info("Sending Login Command...")
        response = self.send_command(login_cmd)

        if response:
            logger.info(f"Login Response: {response}")
            # Check for success (usually result: 0)
            if response.get("result", -1) == 0:
                # Extract token if available
                if "token" in response:
                    self.token = response["token"]
                    logger.info(f"Token updated: {self.token}")
                return True

        logger.error("Login failed or invalid response.")
        return False

    def send_heartbeat(self):
        """
        Sends the Heartbeat command (cmdId: 525).
        Should be called regularly to keep connection alive.
        """
        cmd = {"cmdId": 525}
        # logger.debug("Sending Heartbeat...")
        # Heartbeats often don't return meaningful data, so we might ignore the return
        self.send_command(cmd)

    def get_device_info(self):
        """
        Sends cmdId: 512 to get status (battery, sd card, etc).
        Returns the dictionary response.
        """
        cmd = {"cmdId": 512}
        logger.info("Requesting Device Info...")
        return self.send_command(cmd)

    def start_stream(self):
        """
        Sends cmdId: 258 to Start Live View / Initialize Session.
        """
        cmd = {"cmdId": 258}
        logger.info("Starting Live Stream Session...")
        return self.send_command(cmd)

    def stop_stream(self):
        """
        Sends cmdId: 259 to Stop Live View.
        """
        cmd = {"cmdId": 259}
        logger.info("Stopping Live Stream Session...")
        return self.send_command(cmd)
