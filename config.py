# Configuration for KJK230 Trail Camera Controller

# ==============================================================================
# [CRITICAL] REVERSE ENGINEERING DATA REQUIRED
# You must fill these values based on your findings from the HCI Snoop Log.
# See README.md for instructions.
# ==============================================================================

# BLE Configuration
# The MAC address of the camera's BLE interface.
BLE_MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"

# The Service UUID found during the write operation.
SERVICE_UUID = "0000xxxx-0000-1000-8000-00805f9b34fb"

# The Characteristic UUID used to send the wakeup command.
CHAR_UUID = "0000xxxx-0000-1000-8000-00805f9b34fb"

# The "Magic Packet" payload. This is the hex byte sequence sent to the characteristic.
# Example: bytearray.fromhex("aa01050000000000")
WAKEUP_PAYLOAD = bytearray.fromhex("00000000")

# ==============================================================================
# WIFI Configuration
# ==============================================================================

# The prefix of the Camera's WiFi SSID.
# The script will scan for SSIDs starting with this string.
WIFI_SSID_PREFIX = "KJK230-"

# The WiFi password for the camera.
# Common defaults are '12345678', '1234567890', or empty.
WIFI_PASSWORD = "12345678"

# ==============================================================================
# HTTP API Configuration
# ==============================================================================

# The Base URL for the Camera's Web Server.
# This usually includes the IP and the root path for commands or file access.
# Examples: "http://192.168.1.1/cgi-bin/", "http://192.168.4.1/SD/"
CAM_BASE_URL = "http://192.168.1.1/"

# Directory to save downloaded files
DOWNLOAD_DIR = "./downloads"
