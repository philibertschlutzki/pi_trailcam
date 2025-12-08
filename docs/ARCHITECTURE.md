# System Architecture
+
+This document provides a high-level overview of the `pi_trailcam` system architecture, explaining how the different modules interact to establish a connection with the KJK230 Trail Camera.
+
+## System Overview
+
+The system is designed as a modular pipeline that mirrors the connection lifecycle of the camera:
+
+1.  **BLE Manager** finds the camera and initiates the wake-up.
+2.  **BLE Token Listener** extracts the authentication token and sequence number.
+3.  **WiFi Manager** connects to the camera's AP.
+4.  **Camera Client** establishes the UDP connection (PPPP + Artemis) and logs in.
+5.  **PPPP Wrapper** handles the low-level packet encapsulation.
+
+### Data Flow Diagram
+
+```mermaid
+graph TD
+    A[Main Controller] --> B[BLE Manager]
+    B --> C{Camera Found?}
+    C -- Yes --> D[BLE Token Listener]
+    D -- Token + Seq --> E[WiFi Manager]
+    E -- Connected --> F[Camera Client]
+    F -- PPPP Packets --> G[Camera UDP Service]
+
+    subgraph Protocol Stack
+    F --> H[PPPP Wrapper]
+    H --> F
+    end
+```
+
+## Module Responsibilities
+
+### `modules/ble_manager.py`
+- **Role:** Device Discovery & Wake-up
+- **Function:** Scans for BLE devices matching the camera's signature. Connects to the device to trigger the wake-up sequence.
+- **Key Dependencies:** `bleak`
+
+### `modules/ble_token_listener.py`
+- **Role:** Credential Extraction
+- **Function:** Subscribes to the specific BLE notification characteristic. Parses the incoming data stream to extract the authentication token (JSON or binary) and the Artemis sequence number.
+- **Key Insight:** Must handle packet fragmentation and different token formats (see `docs/PROTOCOL_ANALYSIS.md`).
+
+### `modules/wifi_manager.py`
+- **Role:** Network Management
+- **Function:** Manages the WiFi interface using `nmcli`. Scans for the camera's hotspot (SSID usually starts with "KJK_") and connects using the password derived from the name or configuration.
+
+### `modules/camera_client.py`
+- **Role:** UDP Connection & Session Management
+- **Function:**
+    - Implements the 3-phase connection flow (Init, Discovery, Login).
+    - Manages UDP socket lifecycle, including source port binding (Firewall traversal).
+    - Maintains the session heartbeat.
+- **State Machine:** `DISCONNECTED` → `INITIALIZING` → `DISCOVERING` → `CONNECTING` → `AUTHENTICATED`.
+
+### `modules/pppp_wrapper.py`
+- **Role:** Protocol Encapsulation
+- **Function:** Wraps Artemis application-layer payloads into PPPP transport-layer packets.
+- **Key Insight:** Maintains the PPPP sequence number (transport) separate from the Artemis sequence number (application).
+
+## Sequence Numbers
+
+The system maintains two distinct sequence counters, as revealed in the protocol analysis:
+
+1.  **PPPP Sequence (`pppp_wrapper.py`):**
+    - Increments with *every* packet sent over UDP.
+    - Used by the PPPP transport layer to ensure packet ordering and reliability.
+    - Resets to 1 at the start of a new UDP session.
+
+2.  **Artemis Sequence (`camera_client.py`):**
+    - Sourced from the BLE handshake.
+    - Used in the payload of Discovery and Login packets.
+    - Identifies the specific application session.
+
+## Error Handling & Recovery
+
+*   **BLE Timeout:** If token is not received, the system retries the BLE connection.
+*   **WiFi Connection Failed:** Retries with exponential backoff.
+*   **UDP Login Timeout:**
+    - The `CameraClient` iterates through a list of known "allowed" source ports (`config.DEVICE_PORTS`).
+    - If a port fails, it closes the socket and tries the next one.
+    - This works around the camera's strict firewall rules.
+
+## Integration with Protocol Analysis
+
+This architecture directly implements the findings in `docs/PROTOCOL_ANALYSIS.md`:
+
+*   **Phase 1 (Init):** Implemented in `CameraClient._send_init_packets()` calling `PPPPWrapper.wrap_init()`.
+*   **Phase 2 (Discovery):** Implemented in `CameraClient.discovery_phase()`.
+*   **Phase 3 (Login):** Implemented in `CameraClient.login()` using `PPPPWrapper.wrap_login()` with Type `0xD0`.
+
+For a detailed breakdown of the byte-level protocol, refer to `docs/PROTOCOL_ANALYSIS.md`.
+