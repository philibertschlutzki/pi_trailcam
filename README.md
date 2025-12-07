# KJK230 Trail Camera Controller

A complete, ready-to-run Python automation project for the KJK230 Trail Camera on Raspberry Pi.

## Overview
This project automates the connection sequence:
1.  **BLE Wakeup:** Finds and wakes the camera using Bluetooth Low Energy.
2.  **WiFi Connection:** Automatically connects to the camera's AP.
3.  **UDP Control:** Logs in, manages session heartbeat, and retrieves status via the proprietary binary/JSON protocol.

## Prerequisites

*   Raspberry Pi (Zero W, 3, 4, 5) with WiFi and Bluetooth.
*   Raspberry Pi OS (Debian based).
*   `nmcli` (NetworkManager) installed and managing interfaces.

## Installation
0.1 Oneliner
```bash
sudo rm -rf pi_trailcam/ && git clone https://github.com/philibertschlutzki/pi_trailcam.git && cd pi_trailcam && python3 -m venv venv && source venv/bin/activate && pip3 install -r requirements.txt && sudo ./venv/bin/python3 main.py
```
1.  Clone the repo:
    ```bash
    git clone <repo_url>
    cd <repo_dir>
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

    *If you are on an older OS (Bullseye), you can simply run `pip3 install -r requirements.txt` globally.*

## Configuration

Edit `config.py` if you need to override defaults.
*   **BLE_MAC_ADDRESS**: If set to `None`, the script will scan for "KJK..." devices. If known, set it (e.g., `"AA:BB:CC:DD:EE:FF"`) for faster startup.

## Usage

**Important:** Because this script manages hardware (Bluetooth/WiFi), it requires root privileges (`sudo`). When using a virtual environment, you must point `sudo` to the python executable *inside* the venv.

```bash
# Example if you are in the project directory
sudo ./venv/bin/python3 main.py
```

## Troubleshooting
*   **WiFi Fails:** Ensure the camera is within range and no other device is currently connected to it.
*   **BLE Fails:** Ensure `bluetoothd` is running (`systemctl status bluetooth`).
