# KJK230 Trail Camera Controller (Artemis/LBCS Protocol)

A complete, ready-to-run Python automation project for the KJK230 Trail Camera (and similar Tuya/Artemis-based clones) on Raspberry Pi.

<img width="440" height="487" alt="image" src="https://github.com/user-attachments/assets/140db893-2e28-41f1-bbde-465088706415" />

**Temu Product ID:** KL2870699
**Firmware:** V2.3.0.4
**Bluetooth:** V3.3.5
**Model:** KJK230D-GW20250908

## 🚀 Overview

This project reverse-engineers and automates the proprietary connection sequence for the KJK230 camera. It handles the entire lifecycle:

1. **BLE Wakeup:** Wakes the camera from deep sleep using Bluetooth Low Energy (characteristic write to UUID `00000002-0000-1000-8000-00805f9b34fb` with 8-byte payload).
2. **WiFi Auto-Connect:** Connects the Raspberry Pi to the camera's hotspot (`KJK_E0FF`) using `nmcli` (NetworkManager CLI).
3. **LBCS Discovery:** Sends proprietary UDP discovery packets to ports `40611` and `3333` to wake the camera's network stack.
4. **Pre-Login Authentication:** Encrypts a JSON payload (with timestamp and nonce) using AES-128-ECB and the fixed key `a01bc23ed45fF56A`.
5. **ARTEMIS Session Establishment:** Sends a hardcoded session-start packet and enters an event loop.
6. **Heartbeat & Event Handling:** Maintains connection with periodic heartbeat packets (every 2 seconds) and filters received packets by size to reduce log spam.

## 🛠️ The Protocol (Reverse Engineering Findings)

The camera uses a multi-stage protocol referred to as **"Artemis"** or **"LBCS"**.

### 1. Network Topology

- **Camera IP:** `192.168.43.1` (created by camera's hotspot)
- **Command Port:** `40611` (UDP) - Main communication endpoint
- **Fallback Port:** `3333` (UDP) - Alternative discovery/fallback
- **Client Local Port:** `35281` (UDP) - Binds to this port (mimics official Android app for potential port-filtering bypass)

### 2. BLE Wake-Up Characteristic

Unlike WiFi, the camera requires a specific Bluetooth Low Energy trigger to activate the network stack:

- **Service/Characteristic UUID:** `00000002-0000-1000-8000-00805f9b34fb`
- **Payload:** `13 57 01 00 00 00 00 00` (8 bytes, fixed)
- **Expected Duration:** ~15 seconds before WiFi radio activates
- **Discovery:** Use `sudo hcitool lescan` to find your camera's BLE MAC address (often named "KJK..." or similar)

### 3. LBCS Discovery Sequence

Before login, the camera's network stack is "dormant". You **must** trigger it with the LBCS discovery:

1. **LBCS Payload:** `F1 41 00 14 4C 42 43 53 ... [20-byte LBCS header]`
   - Magic bytes: `F1 41`
   - Response filter: Look for `F1 42` (LBCS Response) or `F1 D0` (ACK)

2. **Timeout:** If no response within 5 seconds on port 40611, retry on port 3333

3. **Success Indicator:** Receiving a response with header byte `0xF1` and type byte `0x42` or `0xD0`

### 4. Pre-Login (Authentication) Phase

After discovery succeeds, send encrypted login credentials:

- **Command Type:** `0xF9` (PRE_LOGIN)
- **Encryption:** AES-128-ECB
- **Key:** `a01bc23ed45fF56A` (16 bytes, ASCII, hardcoded in firmware)
- **Plaintext:** JSON with `utcTime` (current Unix timestamp) and `nonce` (8 random bytes, hex-encoded)
- **Static Header:** 28-byte prefix before encrypted payload (from reverse engineering)

### 5. ARTEMIS Session Layer

After successful login, initiate the main session:

- **Command Type:** `0xD0` (ARTEMIS Hello)
- **Packet Structure:** `[Magic 0xF1] [Type] [Length: 2 bytes big-endian] [Payload]`
- **Session Payload:** Hardcoded 160-byte hello packet containing base64-encoded session token
- **Heartbeat:** Send `F1 D1 00 0E ...` every 2 seconds to maintain connection

### 6. Event Filtering

The main loop receives status packets and events. Packet filtering by size reduces spam:

- **Ignored Sizes:** 40 bytes (standard status), 157 bytes (status variant), 11 bytes ending with "ACK" (acknowledgments), 4 bytes `F1 E0 00 00` (ping responses)
- **Logged Sizes:** Everything else (commands, events, firmware updates)

## 📋 Prerequisites

- **Hardware:** Raspberry Pi (Zero 2 W, 3, 4, 5) with WiFi and Bluetooth
- **OS:** Raspberry Pi OS (Debian Bookworm recommended)
- **System Tools:** 
  - `nmcli` (NetworkManager) for WiFi management
  - `hcitool` (BlueZ) for Bluetooth scanning (optional, for discovering BLE MAC)
  - `sudo` access for Bluetooth and WiFi control

## 📦 Installation

### Quick Start (One-Liner)

This command clones the repo, sets up a virtual environment, installs dependencies, and runs the script:

```bash
sudo rm -rf pi_trailcam/ && git clone https://github.com/philibertschlutzki/pi_trailcam.git && cd pi_trailcam && python3 -m venv venv && source venv/bin/activate && pip3 install -r requirements.txt && sudo ./venv/bin/python3 main.py --ble --wifi
```

### Manual Setup

1. **Clone the Repository:**
```bash
git clone https://github.com/philibertschlutzki/pi_trailcam.git
cd pi_trailcam
```

2. **Setup Virtual Environment (Required for Bookworm+):**
```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install Dependencies:**
```bash
pip3 install -r requirements.txt
```

**Dependencies:**
- `bleak` (0.20.1) - Bluetooth Low Energy client for BLE wakeup
- `pycryptodome` (≥3.19.0) - AES-128-ECB encryption for authentication
- `netifaces` (≥0.11.0) - Network interface detection (used for obtaining local IP)
- `scapy` (≥2.5.0) - Listed but not currently used in main.py (available for protocol analysis)

## ⚙️ Usage

**Important:** You must run the script with `sudo` because it needs low-level access to Bluetooth and WiFi hardware via `nmcli` and `bleak`.

### Full Auto Mode

Wakes the camera via BLE, connects to WiFi, and starts the session:

```bash
sudo ./venv/bin/python3 main.py --ble --wifi
```

**Flow:**
1. Connects to camera via BLE characteristic write
2. Waits 15 seconds for WiFi radio to activate
3. Runs `nmcli` to connect to the hotspot
4. Performs LBCS discovery
5. Executes pre-login authentication
6. Sends ARTEMIS hello and enters event loop

### Session-Only Mode

If you are already connected to the camera's WiFi (`KJK_E0FF`), skip the setup steps:

```bash
sudo ./venv/bin/python3 main.py
```

### BLE-Only (Wakeup Test)

Test BLE connectivity without WiFi connection:

```bash
sudo ./venv/bin/python3 main.py --ble
```

### WiFi-Only (Connection Test)

Test WiFi connection without BLE wakeup (useful if camera is already semi-active):

```bash
sudo ./venv/bin/python3 main.py --wifi
```

## 🔧 Configuration

All configuration is done via constants at the top of `main.py`. Key parameters:

- **`BLE_MAC`** (default: `C6:1E:0D:E0:32:E8`)
  - Bluetooth MAC address of your specific camera
  - Find it with: `sudo hcitool lescan | grep KJK`

- **`DEFAULT_SSID`** (default: `KJK_E0FF`)
  - WiFi SSID broadcast by the camera
  - If your camera uses a custom name, update this

- **`DEFAULT_PASS`** (default: `85087127`)
  - WiFi password (same across all KJK230 devices, hardcoded in firmware)

- **`TARGET_IP`** (default: `192.168.43.1`)
  - Camera's IP when it creates the hotspot (don't change)

- **`TARGET_PORTS`** (default: `[40611, 3333]`)
  - Ports used for LBCS discovery and command communication

- **`FIXED_LOCAL_PORT`** (default: `35281`)
  - Local UDP port to bind to (mimics Android app)
  - Change only if port is already in use on your system

## 🐛 Troubleshooting

| Issue | Likely Cause | Solution |
|-------|--------------|----------|
| **`Network is unreachable`** | Not connected to camera WiFi | Manually connect to `KJK_E0FF` or run with `--wifi` flag |
| **`BLE Error / Device not found`** | Incorrect BLE MAC or camera in wrong state | 1. Verify MAC with `hcitool lescan` 2. Restart camera (long power button press) 3. Try again with `--ble` flag |
| **`Handshake failed` / No LBCS response | Camera network stack not active | 1. Ensure `--ble` flag triggered wakeup 2. Wait 15+ seconds after BLE write 3. Verify camera is powered on |
| **`Permission denied` on socket/nmcli** | Not running as root | Prepend `sudo` to command |
| **`Key-mgmt error` in nmcli output** | Old WiFi profile still cached | Script automatically deletes old profile; if persistent, run `sudo nmcli c delete KJK_E0FF` manually |
| **Connection times out / Heartbeat errors** | Network interference or camera firmware issue | 1. Move closer to camera 2. Check 2.4GHz WiFi channel congestion 3. Try powering off/on camera |

## 📂 Project Structure

```
pi_trailcam/
├── main.py                      # Core controller with all protocol logic
├── requirements.txt             # Python dependencies
├── README.md                    # This file
└── docs/
    ├── PROTOCOL_ANALYSIS.md     # Detailed Artemis/LBCS protocol breakdown
    ├── ARCHITECTURE.md          # System design and reverse engineering notes
    ├── COMMAND_IDS_AND_PAYLOADS.md  # Documented command types and example payloads
    ├── HEARTBEAT_AND_COMMANDS.md    # Heartbeat structure and status packet format
    └── BYTE_ORDER_VALIDATION.md     # Endianness verification and struct packing
```

## 🔍 What's Actually Running

`main.py` is a **single-file, synchronous UDP client** that:

1. **Manages BLE wakeup** via the `BleakScanner` and `BleakClient` from the `bleak` library
2. **Manages WiFi connection** by shelling out to `nmcli` commands (requires `sudo`)
3. **Manages socket lifecycle**:
   - Binds to local port `35281` (with OS fallback if busy)
   - Sends LBCS discovery payloads
   - Receives and parses responses
   - Maintains single long-lived UDP socket

4. **Handles encryption** for pre-login phase using `pycryptodome`'s AES-ECB
5. **Filters packet spam** using packet size heuristics
6. **Maintains heartbeat** with 2-second intervals

**Not implemented (future work):**
- Parallel connection threads (mentioned in some docs but not in current code)
- Command sending beyond session establishment
- Relay server support (only P2P/LAN direct connection)
- Persistent session recovery or reconnection logic

## 📝 License

This is a reverse-engineering and educational project. Use at your own discretion. The protocol and payloads are derived from analyzing the Android app's binary protocol, not official documentation.

## 🙏 Contributing

Contributions are welcome! Areas for enhancement:
- Command implementation (e.g., trigger recording, adjust settings)
- Improved error recovery and reconnection logic
- Protocol documentation improvements
- Hardware compatibility testing across Pi models
