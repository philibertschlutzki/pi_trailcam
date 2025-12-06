# KJK230 Trail Camera Controller

A complete, ready-to-run Python automation project for the KJK230 Trail Camera on Raspberry Pi.

## Overview
This project automates the connection sequence:
1.  **BLE Wakeup:** Finds and wakes the camera using Bluetooth Low Energy.
2.  **WiFi Connection:** Automatically connects to the camera's AP.
3.  **TCP Control:** Logs in and retrieves status via the proprietary JSON protocol.

## Prerequisites

*   Raspberry Pi (Zero W, 3, 4, 5) with WiFi and Bluetooth.
*   Raspberry Pi OS (Debian based).
*   `nmcli` (NetworkManager) installed and managing interfaces.

## Installation

1.  Clone the repo:
    ```bash
    git clone <repo_url>
    cd <repo_dir>
    ```
2.  Install dependencies:
    ```bash
    pip3 install -r requirements.txt
    ```

## Configuration

Edit `config.py` if you need to override defaults.
*   **BLE_MAC_ADDRESS**: If set to `None`, the script will scan for "KJK..." devices. If known, set it (e.g., `"AA:BB:CC:DD:EE:FF"`) for faster startup.

## Usage

Run the main script with sudo (needed for BLE/WiFi access):

```bash
sudo python3 main.py
```

## Troubleshooting
*   **WiFi Fails:** Ensure the camera is within range and no other device is currently connected to it.
*   **BLE Fails:** Ensure `bluetoothd` is running (`systemctl status bluetooth`).
