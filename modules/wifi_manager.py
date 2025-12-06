import subprocess
import time
import logging
import config  # Wir greifen auf die zentralen Konstanten zu

class WiFiManager:
    def __init__(self):
        self.ssid_prefix = config.WIFI_SSID_PREFIX
        self.password = config.WIFI_PASSWORD

    def _run_command(self, cmd_list):
        """Hilfsfunktion um Shell-Befehle sicher auszuführen."""
        try:
            result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                check=False
            )
            return result
        except Exception as e:
            logging.error(f"Error executing command {' '.join(cmd_list)}: {e}")
            return None

    def _clean_existing_profile(self, ssid):
        """Löscht alte/korrupte Profile, um 'key-mgmt' Fehler zu vermeiden."""
        logging.info(f"Cleaning up potential old profiles for '{ssid}'...")
        # Wir ignorieren den Output, da es okay ist, wenn das Profil nicht existiert
        self._run_command(["sudo", "nmcli", "connection", "delete", "id", ssid])
        time.sleep(1) # Kurze Pause für den NetworkManager

    def scan_for_camera(self):
        """Scannt nach Netzwerken und gibt die volle SSID zurück, die mit dem Prefix startet."""
        logging.info(f"Scanning for WiFi starting with '{self.ssid_prefix}'...")
        
        # 1. Trigger Rescan (hilft oft, wenn SSID frisch aufgetaucht ist)
        self._run_command(["sudo", "nmcli", "device", "wifi", "rescan"])
        time.sleep(2) 

        # 2. Liste abrufen
        result = self._run_command(["sudo", "nmcli", "-t", "-f", "SSID", "dev", "wifi"])
        
        if not result or result.returncode != 0:
            logging.warning("WiFi scan failed or returned no output.")
            return None

        # 3. Parsen
        ssids = result.stdout.strip().split('\n')
        for ssid in ssids:
            if ssid.startswith(self.ssid_prefix):
                logging.info(f"Found Camera SSID: {ssid}")
                return ssid
        
        return None

    def connect_to_camera_wifi(self):
        """Hauptfunktion: Scannt, bereinigt und verbindet."""
        
        # Versuche mehrmals, das WLAN zu finden (Kamera braucht oft Zeit nach BLE Wakeup)
        target_ssid = None
        for attempt in range(3):
            target_ssid = self.scan_for_camera()
            if target_ssid:
                break
            logging.info("SSID not found yet, retrying scan...")
            time.sleep(2)

        if not target_ssid:
            logging.error("Camera WiFi not found after multiple scans.")
            return False

        # WICHTIG: Altes Profil löschen (Fix für Ihren Fehler)
        self._clean_existing_profile(target_ssid)

        logging.info(f"Attempting to connect to {target_ssid}...")
        
        # Verbindungsbefehl mit sudo
        cmd = [
            "sudo", "nmcli", "dev", "wifi", "connect", target_ssid,
            "password", self.password
        ]
        
        result = self._run_command(cmd)

        if result and result.returncode == 0:
            logging.info(f"Successfully connected to {target_ssid}")
            
            # Optional: Kurz warten bis DHCP IP zugewiesen hat
            time.sleep(3) 
            return True
        else:
            error
