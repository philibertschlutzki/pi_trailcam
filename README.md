# KJK230 Trail Camera Controller (Raspberry Pi)

This project provides a Python-based automation suite to control a **KJK230 Trail Camera** using a Raspberry Pi. It mimics the behavior of the proprietary "Trail Cam Go" app by interacting with the camera's Bluetooth Low Energy (BLE) interface to wake up its WiFi Access Point, connecting to it, and downloading media files.

## ⚠️ Prerequisites & Disclaimer

**This software is for educational and interoperability purposes.**
You will need to perform some initial **Reverse Engineering** to find the unique keys and identifiers for your specific camera model. This guide assumes you are using an Android phone to capture the initial traffic.

---

## 🛠️ Critical Reverse Engineering Guide

Before running this code, you must obtain the following values:
1.  **BLE Service UUID**
2.  **BLE Characteristic UUID** (used for writing the wakeup command)
3.  **Wakeup "Magic Packet"** (Hex payload)
4.  **Camera IP Address & API Endpoints**

### Step 1: Enable HCI Snoop Logging (Android)
1.  On your Android phone, go to **Settings > About Phone**.
2.  Tap **Build Number** 7 times to enable **Developer Options**.
3.  Go to **Settings > System > Developer Options**.
4.  Enable **Enable Bluetooth HCI snoop log**.
5.  Toggle Bluetooth OFF and then ON again to restart the logging service.

### Step 2: Capture the Wakeup Sequence
1.  Open the "Trail Cam Go" app.
2.  Stand near the camera (ensure it is in "Standby" mode).
3.  Trigger the "Connect" or "Turn on WiFi" action in the app.
4.  Wait for the phone to connect to the camera's WiFi and show the live view or file list.
5.  **Stop** doing anything and close the app.
6.  Go back to **Developer Options** and disable HCI logging.

### Step 3: Analyze the Log in Wireshark
1.  Connect your phone to a PC/Mac via USB.
2.  Extract the `btsnoop_hci.log` file (usually in `/sdcard/` or generated via `adb bugreport`).
    *   *Tip: Use `adb pull /sdcard/btsnoop_hci.log` if you have ADB installed.*
3.  Open the log file in **Wireshark**.
4.  Filter for **Write Command** or **Write Request** (enter `btatt.opcode == 0x12` or `btatt.opcode == 0x52` in the filter bar).
5.  Look for a packet sent **from your phone (Host)** to the **Camera (Remote)** right before the WiFi connection starts.
6.  **Note down:**
    *   **Destination MAC Address**: The BLE MAC address of the camera.
    *   **Service UUID**: The 128-bit UUID of the service.
    *   **Characteristic UUID**: The 128-bit UUID where the data was written.
    *   **Value (Hex)**: The byte sequence sent (e.g., `aa010000...`). This is the `WAKEUP_PAYLOAD`.

### Step 4: Find HTTP Endpoints
1.  Once connected to the Camera's WiFi, you can use a Packet Capture app on your phone (like "PCAPdroid" or "NetCapture") OR simply use Wireshark on your PC if you connect your PC's WiFi to the Camera.
2.  Perform actions in the app (List files, Download a photo).
3.  Look for HTTP GET requests.
4.  **Note down:**
    *   **Camera IP**: Usually `192.168.1.1` or similar.
    *   **Base URL**: E.g., `http://192.168.1.1/cgi-bin/` or `http://192.168.1.1/SD/`.

---

## 🚀 Setup & Installation

1.  **Clone this repository** to your Raspberry Pi.
2.  **Install System Dependencies:**
    ```bash
    sudo apt-get update
    sudo apt-get install python3-pip network-manager
    ```
    *Ensure `NetworkManager` is managing your WiFi interfaces.*

3.  **Install Python Dependencies:**
    ```bash
    pip3 install -r requirements.txt
    ```

4.  **Configure the Project:**
    Open `config.py` and fill in the values you found in the Reverse Engineering section.
    ```python
    nano config.py
    ```

5.  **Run:**
    ```bash
    sudo python3 main.py
    ```
    *(Sudo is often required for Bluetooth/WiFi control on Linux).*

## 📂 Project Structure

*   `main.py`: The master script.
*   `config.py`: Configuration file for UUIDs, Keys, and WiFi creds.
*   `modules/ble_handler.py`: Handles BLE connection and "Magic Packet" sending.
*   `modules/wifi_handler.py`: Manages WiFi scanning and connection using `nmcli`.
*   `modules/http_client.py`: Handles HTTP API communication (listing/downloading files).
