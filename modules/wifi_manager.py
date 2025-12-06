import subprocess
import time
import logging
import config

logger = logging.getLogger(__name__)

class WiFiManager:
    """
    Handles WiFi scanning and connection using NetworkManager (nmcli).
    """

    def _run_command(self, command_list):
        """Helper to run shell commands safely without shell=True."""
        try:
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

    def connect_to_camera_wifi(self, timeout=60):
        """
        Scans for SSIDs starting with the configured prefix ("KJK_") and connects.

        Args:
            timeout (int): Max time in seconds to search and connect.

        Returns:
            bool: True if connected, False otherwise.
        """
        logger.info(f"Looking for WiFi SSID starting with '{config.WIFI_SSID_PREFIX}'...")
        start_time = time.time()
        found_ssid = None

        # 1. Scan loop
        while (time.time() - start_time) < timeout:
            # Rescan
            self._run_command(["nmcli", "dev", "wifi", "rescan"])
            time.sleep(2)

            # List
            output = self._run_command(["nmcli", "-t", "-f", "SSID", "dev", "wifi", "list"])
            if output:
                ssids = output.split('\n')
                for ssid in ssids:
                    ssid = ssid.strip()
                    if ssid.startswith(config.WIFI_SSID_PREFIX):
                        logger.info(f"Found Camera WiFi: {ssid}")
                        found_ssid = ssid
                        break

            if found_ssid:
                break

            logger.debug("Camera SSID not found yet...")
            time.sleep(3)

        if not found_ssid:
            logger.error("Timeout: Camera WiFi SSID not found.")
            return False

        # 2. Connect
        logger.info(f"Connecting to {found_ssid}...")
        # nmcli dev wifi connect <SSID> password <PASSWORD>
        cmd = ["nmcli", "dev", "wifi", "connect", found_ssid, "password", config.WIFI_PASSWORD]

        if self._run_command(cmd):
            logger.info(f"Successfully connected to {found_ssid}")
            # Wait for DHCP / Network stability
            time.sleep(5)
            return True
        else:
            logger.error(f"Failed to connect to {found_ssid}")
            return False
