# Configuration for KJK230 Trail Camera Controller

# ==============================================================================
# [CRITICAL] REVERSE ENGINEERING DATA REQUIRED
# The user must sniff the BLE traffic to find the 8-byte payload.
# ==============================================================================

# BLE Configuration
# The MAC address of the camera's BLE interface.
BLE_MAC_ADDRESS = "AA:BB:CC:DD:EE:FF"

# The Service UUID.
BLE_SERVICE_UUID = "00008800-0000-1000-8000-00805f9b34fb"

# The Characteristic UUID used to send the wakeup command.
BLE_CHAR_UUID = "00008801-0000-1000-8000-00805f9b34fb"

# The 8-byte "Magic Packet" payload.
# REPLACE THIS with the hex string found in your HCI Snoop Log.
BLE_PAYLOAD_HEX = "0000000000000000"

# ==============================================================================
# WIFI Configuration
# ==============================================================================

# The prefix of the Camera's WiFi SSID.
WIFI_SSID_PREFIX = "KJK_"

# The WiFi password for the camera (Static based on findings).
WIFI_PASSWORD = "85087127"

# ==============================================================================
# TCP API Configuration
# ==============================================================================

# The Gateway IP Address of the Camera AP.
CAM_IP = "192.168.43.1"

# The TCP Port for the proprietary control protocol.
CAM_PORT = 40611
