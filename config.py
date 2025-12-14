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

# FIX #25: Camera UDP stack initialization timing
# After BLE wakeup, the camera's UDP stack needs time to initialize.
# Original app (TrailCam Go) shows ~7-8 second delay before successful discovery.
# This delay is applied AFTER WiFi connection established.
# FIX #33: Reduced startup delay to 1s as logs show instant connection is possible
CAMERA_STARTUP_DELAY = 0.5  # seconds

ARTEMIS_DISCOVERY_TIMEOUT = 5  # seconds (increased from 3)
ARTEMIS_LOGIN_TIMEOUT = 5  # seconds
ARTEMIS_KEEPALIVE_INTERVAL = 3  # seconds (heartbeat)

# Connection Retry Configuration
MAX_CONNECTION_RETRIES = 5
RETRY_BACKOFF_SEQUENCE = [1, 2, 4, 8, 16]  # seconds
MAX_TOTAL_CONNECTION_TIME = 90  # seconds (increased from 60 to allow more retries)

# ==============================================================================
# Port Knocking Configuration - OPTIMIZED
# ==============================================================================
# FIX #27: Port sequence optimization based on empirical analysis
#
# ROOT CAUSE ANALYSIS:
# The iOS app (TrailCam Go) successfully connects via port 57743.
# However, port knocking sequence matters for Linux/Raspberry Pi.
# 
# STRATEGY:
# According to tcpdump analysis and iOS app behavior:
# 1. Linux cannot use 57743 on initial connection (app initiates from there POST-WiFi)
# 2. Source port 40611 (client) → 40611 (camera) works as fallback match
# 3. Ephemeral ports (59130, 3014, 47304, 59775) are tried before 57743
# 4. Port 57743 used ONLY after WiFi is established (FIX #25 pattern)
#
# ORDERING PRINCIPLE:
# - Highest priority: 40611 (source-destination match, standard binding)
# - High priority: Ephemeral range attempts (59130, 3014, 47304, 59775)
# - Last resort: 57743 (requires specific initialization timing)
#
# EMPIRICAL DATA FROM LOGS:
# - Issue #27 shows EVERY port times out (no response from camera)
# - Root cause: Token parser rejects token (FIX #26), so WiFi connection fails
# - Port sequence becomes irrelevant without WiFi
# - After FIX #26 (token acceptance), test this port order

DEVICE_PORTS = [
    40611,    # 1st: Source=Destination match (port binding symmetry)
    59130,    # 2nd: Ephemeral - appears in iOS logs
    3014,     # 3rd: Standard ephemeral range
    47304,    # 4th: Ephemeral variant
    59775,    # 5th: Ephemeral variant
    57743,    # 6th: iOS success port, but requires WiFi+init (see FIX #25)
]

# Connection Validation
REQUIRE_DEVICE_DISCOVERY = True
VALIDATE_FIRMWARE_VERSION = True
EXPECTED_FIRMWARE_PATTERN = "2.3.*"
