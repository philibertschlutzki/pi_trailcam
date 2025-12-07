# KJK230 Trail Camera Controller

A complete, ready-to-run Python automation project for the KJK230 Trail Camera on Raspberry Pi.

<img width="440" height="487" alt="image" src="https://github.com/user-attachments/assets/140db893-2e28-41f1-bbde-465088706415" />

Temu Product ID: KL2870699

## Overview
This project automates the connection sequence:
1.  **BLE Wakeup:** Finds and wakes the camera using Bluetooth Low Energy.
2.  **WiFi Connection:** Automatically connects to the camera's AP.
3.  **UDP Control:** Logs in, manages session heartbeat, and retrieves status via the proprietary binary/JSON protocol (Artemis over PPPP).

## PPPP Protocol Layer
This project implements the **PPPP (P2P Push Proxy Protocol)** wrapper required by the camera.
The camera does not accept raw Artemis packets; they must be wrapped in PPPP headers.

Structure:
`[PPPP Outer Header] [PPPP Inner Header] [Artemis Payload]`

- **Magic:** `0xF1`
- **Outer Type:** `0xD1` (Standard), `0xD3` (Control), `0xD4` (Data)
- **Inner Type:** Matches Outer Type
- **Subcommands:** `0x00` (Discovery), `0x03` (Login), `0x01` (Heartbeat/ACK)

See `modules/pppp_wrapper.py` for implementation details.

## Prerequisites

*   Raspberry Pi (Zero W, 3, 4, 5) with WiFi and Bluetooth.
*   Raspberry Pi OS (Debian based).
*   `nmcli` (NetworkManager) installed and managing interfaces.

## Installation

0.0.1 Oneliner Sniffer
```bash
sudo rm -rf pi_trailcam/ && git clone https://github.com/philibertschlutzki/pi_trailcam.git && cd pi_trailcam && python3 -m venv venv && source venv/bin/activate && pip3 install -r requirements.txt && sudo python3 tests/udp_sniffer.py --mitm --target-ip 192.168.43.20 -c 192.168.43.1
```
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
*   **UDP/PPPP Fails:**
    *   Check `modules/pppp_wrapper.py` logs (set logging to DEBUG).
    *   Ensure Sequence Numbers are incrementing correctly.
    *   Verify Magic Byte `0xF1` in responses.
