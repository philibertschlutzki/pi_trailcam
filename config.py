# Configuration for KJK230 Trail Camera Controller

# ==============================================================================
# CONSTANTS (Hardcoded based on Reverse Engineering)
# ==============================================================================

# BLE Configuration
# The Service UUID.
BLE_SERVICE_UUID = "00008800-0000-1000-8000-00805f9b34fb"

# The Characteristic UUID used to send the wakeup command.
BLE_CHAR_UUID = "00000002-0000-1000-8000-00805f9b34fb"

# The 8-byte "Magic Packet" payload.
BLE_PAYLOAD = bytes.fromhex("0100000000000000")

# ==============================================================================
# WIFI Configuration
# ==============================================================================

# The prefix of the Camera's WiFi SSID.
WIFI_SSID_PREFIX = "KJK_"

# The WiFi password for the camera.
WIFI_PASSWORD = "85087127"

# ==============================================================================
# TCP API Configuration
# ==============================================================================

# The Gateway IP Address of the Camera AP.
CAM_IP = "192.168.43.1"

# The TCP Port for the proprietary control protocol.
CAM_PORT = 40611

# ==============================================================================
# User Configuration
# ==============================================================================
# If known, set the MAC address here. Otherwise, the script can scan for it.
# Example: "AA:BB:CC:DD:EE:FF"
BLE_MAC_ADDRESS = "C6:1E:0D:E0:32:E8"

# ==============================================================================
# ARTEMIS Protocol Configuration
# ==============================================================================
ARTEMIS_DISCOVERY_TIMEOUT = 3  # seconds
ARTEMIS_LOGIN_TIMEOUT = 5  # seconds
ARTEMIS_KEEPALIVE_INTERVAL = 3  # seconds (heartbeat)

# Connection Retry Configuration
MAX_CONNECTION_RETRIES = 5
RETRY_BACKOFF_SEQUENCE = [1, 2, 4, 8, 16]  # seconds
MAX_TOTAL_CONNECTION_TIME = 60  # seconds

# Device Ports to Try (in order of likelihood)
DEVICE_PORTS = [40611, 59130, 3014, 47304, 59775, 57743]

# Connection Validation
REQUIRE_DEVICE_DISCOVERY = True
VALIDATE_FIRMWARE_VERSION = True
EXPECTED_FIRMWARE_PATTERN = "2.3.*"
