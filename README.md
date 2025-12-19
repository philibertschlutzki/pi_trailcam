# KJK230 Trail Camera Controller

A complete, ready-to-run Python automation project for the KJK230 Trail Camera on Raspberry Pi.

<img width="440" height="487" alt="image" src="https://github.com/user-attachments/assets/140db893-2e28-41f1-bbde-465088706415" />

Temu Product ID: KL2870699

## Overview
This project automates the connection sequence:
1.  **BLE Wakeup:** Finds and wakes the camera using Bluetooth Low Energy.
2.  **WiFi Connection:** Automatically connects to the camera's AP using `nmcli`.
3.  **UDP Control:** Logs in, manages session heartbeat, and retrieves status via the proprietary binary/JSON protocol (Artemis over PPPP).

The logic is consolidated into a single script `main.py` for ease of use and deployment.

## PPPP Protocol Layer
This project implements the **PPPP (P2P Push Proxy Protocol)** wrapper required by the camera. The camera does not accept raw Artemis packets; they must be wrapped in PPPP headers.

### Protocol Stack (PPPP + Artemis)

The connection process follows a strict sequence:

1.  **Phase 1: Initialization (0xE1)**
    *   Sends magic packets to wake up the camera's UDP stack.
2.  **Phase 2: Discovery/Handshake**
    *   Prepares the channel.
3.  **Phase 3: Login (0xD0)**
    *   Authenticates using the BLE token.
    *   Uses Outer Type `0xD0` (Artemis-specific).

**Structure:** `[PPPP Outer Header] [PPPP Inner Header] [Artemis Payload]`

### UDP Port Binding
The camera's firewall/network stack requires the client to bind to a specific local port to establish communication effectively. The script defaults to binding to port **5085**. If that fails, it falls back to an OS-assigned ephemeral port.

## Prerequisites

*   Raspberry Pi (Zero W, 3, 4, 5) with WiFi and Bluetooth.
*   Raspberry Pi OS (Debian based).
*   `nmcli` (NetworkManager) installed and managing interfaces.

## Installation

### Quick Start (One-Liner)
```bash
sudo rm -rf pi_trailcam/ && git clone https://github.com/philibertschlutzki/pi_trailcam.git && cd pi_trailcam && python3 -m venv venv && source venv/bin/activate && pip3 install -r requirements.txt && sudo ./venv/bin/python3 main.py
```

### Manual Installation
1.  Clone the repo:
    ```bash
    git clone https://github.com/philibertschlutzki/pi_trailcam.git
    cd pi_trailcam
    ```

2.  **Debian Bookworm (Raspberry Pi OS 12) & PEP 668 Note:**
    On newer versions of Raspberry Pi OS, you must use a virtual environment.

    ```bash
    # Create virtual environment
    python3 -m venv venv

    # Activate it
    source venv/bin/activate

    # Install dependencies inside venv
    pip3 install -r requirements.txt
    ```

## Configuration

Configuration is located at the top of `main.py`. You can edit the file directly to change:
*   `CAMERA_BLE_MAC`: Set to your camera's MAC (e.g., `"AA:BB:CC:DD:EE:FF"`) to skip scanning and speed up startup.
*   `CAMERA_IP` / `CAMERA_PORT`: If the camera setup differs (unlikely for this model).
*   `LOCAL_PORT`: The local UDP port to bind to (Default: 5085).

## Usage

**Important:** Because this script manages hardware (Bluetooth/WiFi), it requires root privileges (`sudo`). When using a virtual environment, you must point `sudo` to the python executable *inside* the venv.

```bash
# Example if you are in the project directory
sudo ./venv/bin/python3 main.py
```

## Troubleshooting
*   **WiFi Fails:** Ensure the camera is within range and no other device is currently connected to it. Check `nmcli device wifi list`.
*   **BLE Fails:** Ensure `bluetoothd` is running (`systemctl status bluetooth`).
*   **UDP Fails:** Check the console logs. Ensure the camera IP is reachable (`ping 192.168.43.1`) after WiFi connection.

For technical deep-dives on the protocol, see the documentation in `docs/` and archived analysis in `archive/`.
