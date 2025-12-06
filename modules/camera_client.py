import socket
import json
import time
import logging
import config

logger = logging.getLogger(__name__)

class CameraClient:
    """
    Handles TCP Socket communication with the KJK230 Camera.
    """

    def __init__(self):
        self.ip = config.CAM_IP
        self.port = config.CAM_PORT
        self.sock = None

    def connect(self):
        """Establishes a TCP connection to the camera."""
        logger.info(f"Connecting to Camera TCP Server at {self.ip}:{self.port}...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)
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
            data = self.sock.recv(4096)
            if not data:
                logger.error("Socket closed by remote peer.")
                return None

            response_str = data.decode('utf-8', errors='ignore')
            logger.debug(f"Received: {response_str}")

            try:
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

        # Heuristic check for success (e.g. 'result': 0 or just getting a response)
        if response and isinstance(response, dict):
             # Some cameras return {"result": 0, ...} or just echo data
            logger.info(f"Login Response: {response}")
            return True
        else:
            logger.error("Login failed.")
            return False

    def get_status(self):
        """
        Sends cmdId: 512 to get status (battery, sd card, etc).
        """
        cmd = {"cmdId": 512}
        logger.info("Requesting Status...")
        return self.send_command(cmd)

    def take_photo(self):
        """
        Sends cmdId: 258 (Start Live/Action) or equivalent logic to trigger action.
        """
        # Note: 258 might be "Enter Live View" which enables the stream,
        # actual capture might be another command. Using 258 as requested placeholder.
        cmd = {"cmdId": 258}
        logger.info("Triggering Action (Take Photo/Live View)...")
        return self.send_command(cmd)
