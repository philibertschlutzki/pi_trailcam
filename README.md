# KJK230 Trail Camera Controller (Raspberry Pi)

This project provides a Python-based automation suite to control a **KJK230 Trail Camera** using a Raspberry Pi. It mimics the behavior of the proprietary "Trail Cam Go" app by interacting with the camera's Bluetooth Low Energy (BLE) interface to wake up its WiFi Access Point and then communicating via a raw TCP socket protocol.

## ⚠️ Prerequisites & Disclaimer

**This software is for educational and interoperability purposes.**
You will need to perform some initial **Reverse Engineering** to find the unique keys and identifiers for your specific camera model.

---

## 🛠️ Critical Reverse Engineering Guide

Before running this code, you must obtain the **8-byte BLE Wakeup Payload** and your specific **BLE MAC Address**.

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
4.  Wait for the phone to connect to the camera's WiFi.
5.  **Stop** doing anything and close the app.
6.  Go back to **Developer Options** and disable HCI logging.

### Step 3: Analyze the Log in Wireshark
1.  Extract the `btsnoop_hci.log` file from your phone to your PC.
2.  Open the log file in **Wireshark**.
3.  **FILTER:** Apply the filter `btatt.opcode == 0x12` (Write Request) or `btatt.opcode == 0x52` (Write Command).
4.  **LOCATE THE PACKET:**
    *   Find a packet sent from **Host (Phone)** to **Controller (Camera)** just before the WiFi connection begins.
    *   Verify the **UUID** matches `00008801-0000-1000-8000-00805f9b34fb`.
5.  **EXTRACT DATA:**
    *   Look at the **Value** field.
    *   It should be an **8-byte Hex String** (e.g., `aa01050000000000`).
    *   **THIS IS YOUR `BLE_PAYLOAD_HEX`.**
6.  **EXTRACT MAC:**
    *   Note the **Destination Address** (MAC) of the packet. This is your `BLE_MAC_ADDRESS`.

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
*   `modules/camera_client.py`: Handles TCP Socket communication (JSON Protocol).
