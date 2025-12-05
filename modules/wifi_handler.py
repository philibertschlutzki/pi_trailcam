import subprocess
import time
import logging
import config

logger = logging.getLogger(__name__)

class WifiHandler:
    """
    Handles WiFi scanning and connection using NetworkManager (nmcli).
    """

    def __init__(self):
        self.ssid_prefix = config.WIFI_SSID_PREFIX
        self.password = config.WIFI_PASSWORD
        self.original_connection = None

    def _run_command(self, command_list):
        """Helper to run shell commands safely without shell=True."""
        try:
            # command_list should be a list of strings, e.g. ["ls", "-l"]
            result = subprocess.run(
                command_list,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            # Join the command list for readable logging
            cmd_str = " ".join(command_list)
            logger.error(f"Command failed: {cmd_str}\nError: {e.stderr}")
            return None

    def find_camera_ssid(self, timeout=60):
        """
        Scans for the camera's SSID.

        Args:
            timeout (int): Max time in seconds to search.

        Returns:
            str: The full SSID if found, None otherwise.
        """
        logger.info(f"Scanning for WiFi SSID starting with '{self.ssid_prefix}'...")
        start_time = time.time()

        while (time.time() - start_time) < timeout:
            # Rescan WiFi networks: nmcli dev wifi rescan
            self._run_command(["nmcli", "dev", "wifi", "rescan"])
            time.sleep(2) # Give it a moment to populate

            # List available SSIDs: nmcli -t -f SSID dev wifi list
            output = self._run_command(["nmcli", "-t", "-f", "SSID", "dev", "wifi", "list"])
            if output:
                ssids = output.split('\n')
                for ssid in ssids:
                    # Clean up the SSID string just in case
                    ssid = ssid.strip()
                    if ssid.startswith(self.ssid_prefix):
                        logger.info(f"Found Camera WiFi: {ssid}")
                        return ssid

            logger.debug("Camera SSID not found yet...")
            time.sleep(3)

        logger.error("Timeout: Camera WiFi SSID not found.")
        return None

    def connect_to_camera(self, ssid):
        """
        Connects to the specified SSID using nmcli.
        Saves the current active connection to restore later.

        Args:
            ssid (str): The SSID to connect to.

        Returns:
            bool: True if connected, False otherwise.
        """
        # 1. Save current connection
        # nmcli -t -f NAME connection show --active
        current = self._run_command(["nmcli", "-t", "-f", "NAME", "connection", "show", "--active"])
        if current:
            # Just take the first one if multiple are active (e.g. eth0 and wlan0)
            self.original_connection = current.split('\n')[0]
            logger.info(f"Saved current connection profile: {self.original_connection}")

        logger.info(f"Connecting to {ssid}...")

        # 2. Connect
        # nmcli dev wifi connect <SSID> password <PASSWORD>
        # Note: If the network is open, password part might fail or need adjustment.
        # Most cameras use WPA2.

        # Construct the command list safely
        cmd = ["nmcli", "dev", "wifi", "connect", ssid, "password", self.password]

        if self._run_command(cmd):
            logger.info(f"Successfully connected to {ssid}")
            # Wait for DHCP
            time.sleep(5)
            return True
        else:
            logger.error(f"Failed to connect to {ssid}")
            return False

    def restore_home_wifi(self):
        """
        Restores the previous connection or simply disconnects the camera.
        """
        logger.info("Restoring original WiFi connection...")

        if self.original_connection:
            # Attempt to bring up the old connection
            # nmcli connection up <NAME>
            cmd = ["nmcli", "connection", "up", self.original_connection]
            if self._run_command(cmd):
                logger.info(f"Restored connection to {self.original_connection}")
            else:
                logger.warning(f"Could not restore {self.original_connection}. You may need to reconnect manually.")
        else:
            # If we didn't save one, or it was just a manual disconnect, maybe just scan for known networks?
            # For now, we'll just log.
            logger.info("No previous connection saved to restore.")
