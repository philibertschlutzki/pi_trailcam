import socket
import json
import time
import logging
import config

logger = logging.getLogger(__name__)

class CameraClient:
    """
    Handles TCP Socket communication with the KJK230 Camera.
    Protocol: Raw TCP with JSON payloads.
    """

    def __init__(self):
        self.ip = config.CAM_IP
        self.port = config.CAM_PORT
        self.sock = None
        self.token = None # Token might be needed for subsequent commands

    def connect(self):
        """Establishes a TCP connection to the camera."""
        logger.info(f"Connecting to Camera TCP Server at {self.ip}:{self.port}...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0) # 5 second timeout
            self.sock.connect((self.ip, self.port))
            logger.info("TCP Connection established.")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to TCP server: {e}")
            self.sock = None
            return False

    def close(self):
        """Closes the TCP connection."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        logger.info("TCP Connection closed.")

    def send_command(self, cmd_dict):
        """
        Sends a JSON command and waits for a response.

        Args:
            cmd_dict (dict): The command to send.

        Returns:
            dict: The JSON response parsed as a dictionary, or None if failure.
        """
        if not self.sock:
            logger.error("Cannot send command: Socket not connected.")
            return None

        try:
            # Serialize to JSON and encode to bytes
            payload_str = json.dumps(cmd_dict)
            payload_bytes = payload_str.encode('utf-8')

            logger.debug(f"Sending: {payload_str}")
            self.sock.sendall(payload_bytes)

            # Receive response
            # Note: Protocol details on message framing (e.g., length prefix) are unknown.
            # Assuming for now we can read a chunk and it contains the full JSON response.
            # A more robust implementation would buffer data and look for valid JSON end.
            data = self.sock.recv(4096)
            if not data:
                logger.error("Socket closed by remote peer.")
                return None

            response_str = data.decode('utf-8', errors='ignore')
            logger.debug(f"Received: {response_str}")

            try:
                # Some protocols might concatenate multiple JSONs or have garbage.
                # Attempt standard parse.
                return json.loads(response_str)
            except json.JSONDecodeError:
                logger.warning(f"Received non-JSON response: {response_str}")
                return None

        except Exception as e:
            logger.error(f"Error during send/recv: {e}")
            return None

    def login(self):
        """
        Performs the login handshake (cmdId: 0).
        """
        # RE Findings:
        # {"cmdId":0,"usrName":"admin","password":"admin","needVideo":0,"needAudio":0,"utcTime":<TIMESTAMP>,"supportHeartBeat":true}

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
            # Check for success (assuming 'res': 0 or similar is success, logic inferred)
            # If the response contains a token, store it.
            if "token" in response:
                self.token = response["token"]
                logger.info(f"Token received: {self.token}")
            return True
        else:
            logger.error("Login failed (no response).")
            return False

    def get_device_info(self):
        """
        Requests device info (cmdId: 512).
        """
        # Example: {"cmdId": 512, "token": <TOKEN>}
        if not self.token:
            logger.warning("No token available. Attempting to use dummy token or none.")

        cmd = {
            "cmdId": 512,
            "token": self.token if self.token else 0
        }

        logger.info("Requesting Device Info...")
        response = self.send_command(cmd)

        if response:
            logger.info(f"Device Info: {response}")
            return response
        return None
