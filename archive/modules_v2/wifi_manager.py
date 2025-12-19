import subprocess
import time
import logging
import config

logger = logging.getLogger(__name__)

class WiFiManager:
    """
    Handles WiFi scanning and connection using NetworkManager (nmcli).
    """

    def _run_command(self, command_list, log_errors=True):
        """
        Helper to run shell commands safely without shell=True.
        
        Args:
            command_list (list): The command and arguments.
            log_errors (bool): If False, errors won't be logged (useful for cleanup commands).
        """
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
            if log_errors:
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
            # Rescan to ensure fresh data
            self._run_command(["nmcli", "dev", "wifi", "rescan"])
            time.sleep(2)

            # List available networks
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

        # 2. Cleanup old profiles (CRITICAL FIX for key-mgmt error)
        # We try to delete any existing connection profile with this name.
        # This forces nmcli to re-detect security settings (WPA2 etc.) instead of using a stale config.
        logger.info(f"Cleaning up potential stale profiles for {found_ssid}...")
        self._run_command(["nmcli", "connection", "delete", found_ssid], log_errors=False)
        
        # Give NetworkManager a moment to process the deletion
        time.sleep(1)

        # 3. Connect
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
