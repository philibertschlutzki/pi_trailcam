# KJK230 Trail Camera Controller (Artemis/LBCS Protocol)

A complete, ready-to-run Python automation project for the KJK230 Trail Camera (and similar Tuya/Artemis-based clones) on Raspberry Pi.

<img width="440" height="487" alt="image" src="https://github.com/user-attachments/assets/140db893-2e28-41f1-bbde-465088706415" />
**Temu Product ID:** KL2870699

## 🚀 Overview

This project reverse-engineers and automates the proprietary connection sequence for the KJK230 camera. It handles the entire lifecycle:

1. **BLE Wakeup:** Wakes the camera from deep sleep using a specific Bluetooth Low Energy characteristic write.
2. **WiFi Auto-Connect:** Connects the Raspberry Pi to the camera's hotspot (`KJK_E0FF`) using `nmcli`.
3. **LBCS Handshake:** Performs the mandatory UDP wakeup sequence (`E0` -> `E1` -> `LBCS`) required to open the command port.
4. **Artemis Session:** Authenticates via crypto-token and retrieves device status (Battery, SD Card) via JSON commands.

## 🛠️ The Protocol (Reverse Engineering Findings)

The camera uses a multi-stage protocol often referred to as **"Artemis"** or **"LBCS"**.

### 1. Network Topology

* **Camera IP:** `192.168.43.1`
* 
**Command Port:** `40611` (UDP) 


* **Discovery Port:** `3333` (UDP) - Sometimes used for initial broadcast.
* 
**Client Binding:** The official app binds to local port **35281**. This script mimics this behavior to bypass potential source-port filtering on the camera.



### 2. The Wakeup Sequence (Crucial!)

Unlike standard network devices, the camera's network stack is "dormant" even after WiFi connection. You **must** send this exact UDP sequence to port `40611` before sending any commands:

1. **Wakeup 1 (0xE0):** `F1 E0 00 00`
2. **Wakeup 2 (0xE1):** `F1 E1 00 00`
3. **LBCS Discovery (0x41):** `F1 41 00 14 ... [LBCS Payload]`

*Only after receiving a valid LBCS Response (`0xF1 0x43...`) will the camera accept login packets.*

### 3. Session Layer

* **Encryption:** AES-128-ECB.
* **Structure:** `[Magic 0xF1] [Type] [Length] [Payload]`
* **Payloads:** JSON commands wrapped in a binary Artemis header.

## 📋 Prerequisites

* **Hardware:** Raspberry Pi (Zero 2 W, 3, 4, 5) with WiFi and Bluetooth.
* **OS:** Raspberry Pi OS (Debian Bookworm recommended).
* **System Tools:** `nmcli` (NetworkManager) must be installed and managing the WiFi interface.

## 📦 Installation

### Quick Start (One-Liner)

This command clones the repo, sets up a virtual environment, installs dependencies, and runs the script.

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


*Dependencies include: `bleak` (BLE), `pycryptodome` (AES), `netifaces` (Network Routing).*

## ⚙️ Usage

**Important:** You must run the script with `sudo` because it needs low-level access to Bluetooth and WiFi hardware.

### Full Auto Mode

Wakes the camera via BLE, connects to WiFi, and starts the session.

```bash
sudo ./venv/bin/python3 main.py --ble --wifi

```

### Session Only Mode

If you are already connected to the camera's WiFi (`KJK_E0FF`), skip the setup steps:

```bash
sudo ./venv/bin/python3 main.py

```

## 🔧 Configuration

The script is configured via constants at the top of `main.py`. You may need to adjust:

* **`BLE_MAC`**: The Bluetooth MAC address of your specific camera.
* *Tip:* Run `sudo hcitool lescan` to find your camera's MAC (often named "KJK..." or similar).


* **`DEFAULT_SSID` / `PASS**`: If your camera has a different WiFi name/password.
* **`FIXED_LOCAL_PORT`**: Defaults to `35281` (mimics Android app). Change only if port is busy.

## 🐛 Troubleshooting

| Issue | Solution |
| --- | --- |
| **`Network is unreachable`** | The script couldn't find an interface with IP `192.168.43.x`. Ensure you are connected to the camera WiFi. |
| **`Handshake failed`** | The camera didn't respond to the Wakeup Sequence. 1. Ensure the camera is ON. 2. Verify the BLE MAC address. 3. Try running with `--ble` again to re-trigger the WiFi radio. |
| **BLE Error / Not Found** | The camera only advertises BLE when it's in "standby" (not already connected). Wait 30s or restart the camera. |
| **`Permission denied`** | Are you running with `sudo`? Bluetooth/WiFi control requires root. |

## 📂 Project Structure

* `main.py`: The core controller script. Contains BLE logic, WiFi manager, and the full Artemis/LBCS protocol implementation.
* `requirements.txt`: Python package dependencies.
* `docs/`: (Optional) Protocol dumps and analysis notes.
