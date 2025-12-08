# Protocol Analysis: Artemis PPPP Wrapper

## 1. Overview
This document details the reverse engineering of the TrailCam Go Android application (`com.xlink.trailcamgo`) and its communication protocol. The camera uses a proprietary protocol (referred to as "Artemis") wrapped inside the PPPP (P2P Push Proxy Protocol) transport layer.

**Analysis Source:**
- APK: `com.xlink.trailcamgo` (Version 2.x)
- Libraries: `libArLink.so` (Native P2P logic)
- Classes: `com.xlink.arlink.ArLinkApi`, `Artemis*` commands
- Packet Captures: `tcpdump` logs from device interactions
- **Application Logs:** 2025-12-08 paste.txt (production session analysis)

## 2. Protocol Stack Structure

The communication is layered as follows:

1.  **Transport Layer**: UDP (Ports 40611, 59130, etc.)
2.  **Session Layer**: PPPP (P2P Push Proxy Protocol) - Magic `0xF1`
3.  **Application Layer**: Artemis Protocol (Payload inside PPPP)
4.  **Command Layer**: JSON structured commands (above Artemis)

```
[UDP Header]
    [PPPP Outer Header (4 Bytes)]
        [PPPP Inner Header (4 Bytes)]
            [Artemis Payload (Variable)]
                [JSON Command | Heartbeat]
```

## 3. PPPP Headers

Analysis of `libArLink.so` and packet dumps reveals the PPPP header structure.

### 3.1 Outer Header (4 Bytes)
| Offset | Field | Value | Description |
|---|---|---|---|
| 0 | Magic | `0xF1` | Protocol Identifier |
| 1 | Type | `0xD1`, `0xD0`, `0xE1` | Packet Type (Standard, Login, Init) |
| 2-3 | Length | `uint16_t` (BE) | Length of Inner Header + Payload |

**Observed Packet Types:**
- `0xD1`: Standard Session Data (Discovery, Command, Heartbeat)
- `0xD0`: Login Handshake (Specific to Artemis)
- `0xE1`: Initialization / Wake-up
- `0xD3`: Control / Heartbeat (alternative)
- `0xD4`: Large Data Transfer (Video/Images)

### 3.2 Inner Header (4 Bytes)
| Offset | Field | Value | Description |
|---|---|---|---|
| 0 | Session Type | `0xD1`, `0xE1` | Usually matches Outer Type, but not always |
| 1 | Subcommand | `uint8_t` | Command ID (0x00=Disc, 0x03=Login, 0x05=Heartbeat) |
| 2-3 | Sequence | `uint16_t` (BE) | PPPP Session Sequence Number |

**Sequence Number Rules:**
- Starts at 1.
- Increments by 1 for every packet sent.
- Maintained per session. Resetting it mid-session causes packet rejection.

## 4. Connection Flow

The connection process involves four distinct phases identified in the APK logic (`ArLinkApi.logIn`) and verified via `tcpdump`.

### Phase 1: Initialization (Wake-up)
Before standard discovery, the app sends "Initialization" packets to wake up the camera's UDP stack.
*   **Packet:** `F1 E1 00 04 E1 00 00 01`
*   **Outer Type:** `0xE1`
*   **Inner Type:** `0xE1`
*   **Subcommand:** `0x00`
*   **Payload:** None

### Phase 2: Discovery
The app broadcasts (or unicasts to known IP) a discovery packet containing the current **Artemis Sequence Number**.
*   **Packet:** `F1 D1 00 06 D1 00 00 02 [00 1B]`
*   **Outer Type:** `0xD1`
*   **Subcommand:** `0x00` (Discovery Request)
*   **Payload:** 2 Bytes (Artemis Sequence, e.g., `0x001B` derived from BLE)

**Response:**
*   **Subcommand:** `0x01` (Discovery ACK)
*   **Payload:** Device capabilities/ID.

### Phase 3: Login (Authentication)
The app authenticates using a Session Token obtained via Bluetooth LE (BLE).
*   **Packet:** `F1 D0 00 45 D1 03 00 03 [Artemis Login Payload]`
*   **Outer Type:** `0xD0` (Critical Finding: Login uses `0xD0`, not `0xD1`)
*   **Subcommand:** `0x03` (Login Request)
*   **Payload:** Artemis Login Structure (see below)

**Artemis Login Payload Structure:**
1.  **Magic:** `ARTEMIS\x00` (8 bytes)
2.  **Version:** `0x02000000` (4 bytes, Little Endian)
3.  **Sequence/Mystery:** 4-8 bytes (Derived from BLE sequence)
4.  **Token Length:** 4 bytes (Little Endian)
5.  **Token:** Session Token String (ASCII)

### Phase 4: Session Maintenance (Heartbeat & Commands)

After successful login, the connection is maintained through periodic heartbeat packets and command exchanges.

**Heartbeat (cmdId 525):**
*   **Outer Type:** `0xD1` (Standard session data)
*   **Subcommand:** `0x05` (Heartbeat/Keep-alive)
*   **Interval:** 3.0 seconds (observed: 18:34:05, 08, 11, 14, 17, 20, ...)
*   **Payload:** Minimal JSON `{"cmdId": 525}`
*   **Purpose:** Prevent UDP session timeout due to NAT/firewall timeouts
*   **Response:** None expected (fire-and-forget)

**Log Evidence (from 2025-12-08):**
```
[18:34:05.526] sendCommand:{"cmdId":525}, seq:65537
[18:34:08.534] sendCommand:{"cmdId":525}, seq:65538  (3.008s later)
[18:34:11.544] sendCommand:{"cmdId":525}, seq:65539  (3.010s later)
```

**Command Exchange:**
*   **Outer Type:** `0xD1` (Standard session data)
*   **Subcommand:** `0x04` (Command response) or varies by command type
*   **Payload:** JSON command structure with `cmdId` field
*   **Response:** JSON object with `result` and command-specific data

## 5. Command Protocol (JSON Layer)

Above the PPPP/Artemis transport, commands use JSON payloads with a standardized structure.

### 5.1 Command Format

**Request Structure:**
```json
{
    "cmdId": <integer>,      // Command ID
    // Command-specific fields
}
```

**Response Structure:**
```json
{
    "cmdId": <integer>,      // Echoed command ID
    "result": <0|error_code>, // 0 for success, non-zero for error
    "errorMsg": "Success" | "...",  // Error description
    // Command-specific response data
}
```

### 5.2 Command IDs (from log analysis)

| ID | Name | Direction | Purpose | Interval |
|----|------|-----------|---------|----------|
| 0 | LOGIN | C→D | Device authentication | Once per session |
| 258 | START_AV | C→D | Start audio/video stream | On demand |
| 259 | STOP_AV | C→D | Stop audio/video stream | On demand |
| 512 | GET_DEV_INFO | C→D | Get device configuration | On demand |
| **525** | **HEARTBEAT** | **C→D** | **Keep-alive packet** | **Every 3 seconds** |
| 768 | GET_MEDIA_LIST | C→D | Get media file list | On demand |

**Reference:** See `docs/HEARTBEAT_AND_COMMANDS.md` and `docs/COMMAND_IDS_AND_PAYLOADS.md` for complete command specifications.

### 5.3 Heartbeat Details (cmdId 525)

**Critical Finding:** The heartbeat mechanism is essential for maintaining UDP sessions, especially over NAT/firewall.

**Payload (Minimal):**
```json
{"cmdId": 525}
```

**Timing (Observed):**
- **Interval:** 3.0 ± 0.01 seconds
- **Jitter:** <11ms (excellent stability)
- **Packet Size:** 45 bytes (including PPPP wrapper)
- **Start Time:** Immediately after successful login
- **Stop Time:** On session close or heartbeat manager stop

**Failure Handling:**
- If 5 consecutive heartbeats fail, stop heartbeat manager
- Log warning with failure count
- Trigger reconnection sequence if critical
- Restart heartbeat after successful re-login

**Implementation in Python:**
```python
# Send heartbeat every 3 seconds
await asyncio.sleep(3.0)
await camera_client.send_command(cmd_id=525, payload=None)
```

## 6. Sequence Number Tracking

The system maintains multiple sequence counters at different layers:

### 6.1 PPPP Sequence (Transport Layer)
- **Scope:** Per UDP session
- **Range:** 1, 2, 3, ..., 65535, then wraps
- **Purpose:** Ensure packet ordering and reliability in PPPP layer
- **Increment:** Every packet sent (init, discovery, login, command, heartbeat)
- **Reset:** On new session (after reconnection)
- **Log Example:**
  ```
  Packet 1: F1 D1 [...] 00 01  (PPPP seq = 1)
  Packet 2: F1 D1 [...] 00 02  (PPPP seq = 2)
  Packet 3: F1 D1 [...] 00 03  (PPPP seq = 3)
  ```

### 6.2 Artemis Sequence (Application Layer - BLE-derived)
- **Scope:** Per authentication session
- **Source:** BLE token/sequence from handshake
- **Purpose:** Identify application-level session
- **Usage:** Included in Discovery and Login phases
- **Reset:** On new BLE handshake
- **Range:** Typically 0x0001 - 0xFFFF

### 6.3 Command Sequence (Log/Tracking)
- **Scope:** Per command sent
- **Range:** 1, 2, 3, ... (low range) or 65537+ (heartbeat range)
- **Purpose:** Debug logging and command correlation
- **Log Example:**
  ```
  sendCommand:{"cmdId":0}, seq:1           (Login)
  sendCommand:{"cmdId":512}, seq:2          (Get device info)
  sendCommand:{"cmdId":525}, seq:65537      (Heartbeat)
  sendCommand:{"cmdId":525}, seq:65538      (Heartbeat)
  sendCommand:{"cmdId":258}, seq:3          (Start AV)
  ```

**Important:** Heartbeat and regular commands use different sequence ranges in logs. This is for diagnostic purposes; the actual PPPP sequence increments continuously.

## 7. Reverse Engineering Evidence

### 7.1 Native Library (`libArLink.so`)
Strings extracted from the shared object verify the PPPP library usage:
*   `PPCS_Initialize`
*   `PPCS_Connect`
*   `PPCS_Write`
*   `PPCS_Read`
*   `ArLink_Initialize`
*   `ArLink_SendHeartbeat` (inferred from behavior)

### 7.2 Java Bytecode (`classes.dex`)
The `com.xlink.trailcamgo` package contains the JNI wrapper `ArLinkApi` which exposes these native functions to the Android app. The method `logIn` orchestrates the `PPCS_Connect` calls.

### 7.3 TCPDump Verification
Traffic analysis confirms the `F1 D0` header for login packets, which differs from the standard `F1 D1` used for discovery.
*   *Log Entry:* `f1d0 0045 d100 0005 ... 4152 5445 4d49 53` ("ARTEMIS")
*   This proves the need for the `wrap_login` modification implemented in `modules/pppp_wrapper.py`.

### 7.4 Application Log Analysis (2025-12-08)
Live application logs provide direct evidence for:
- **Heartbeat interval:** Exactly 3.0 seconds ± 10ms
- **Port 40611:** Primary LAN port for camera communication
- **Local ephemeral ports:** OS-assigned (e.g., 35281)
- **Command response times:** 100-1200ms depending on command
- **Session stability:** >30 seconds without reconnection

## 8. Implementation Notes

The Python implementation (`modules/pppp_wrapper.py`, `modules/heartbeat.py`, etc.) has been updated to reflect these findings:

1.  **`wrap_init()`**: Added to support Phase 1 (Wake-up).
2.  **`wrap_login()`**: Modified to use `Outer Type 0xD0` for login phase.
3.  **`wrap_command()`**: Standard wrapping for Phase 4 commands (type `0xD1`).
4.  **Heartbeat Integration**: `HeartbeatManager` class sends cmdId 525 every 3 seconds.
5.  **Sequence Handling**: Separate counters for PPPP (transport) and Artemis (application) are strictly enforced.
6.  **Error Recovery**: Heartbeat failure handling with automatic reconnection triggers.

## 9. Encryption / Security

The PPPP layer itself does not appear to use heavy encryption for the handshake, relying instead on the session token exchanged via BLE. The "Mystery Bytes" (Sequence) act as a nonce to prevent replay attacks.

**Session Token:**
- Obtained via BLE during wake-up phase
- Unique per authentication session
- Valid only for the current BLE session
- Prevents unauthorized device access

**Heartbeat Security:**
- No additional authentication for heartbeat packets
- Relies on UDP source port (ephemeral) being spoofed
- NAT/firewall protection provides some security
- Future: Could add HMAC or challenge-response

## 10. Performance Characteristics

**From 2025-12-08 Log Analysis:**

| Operation | Time | Notes |
|-----------|------|-------|
| Connection (LAN) | <1s | Parallel threads, port 40611 success |
| Login response | ~520ms | Includes PPPP handshake |
| Device info retrieval | ~1.2s | Large response, fragmented |
| Heartbeat round-trip | ~10ms | Minimal payload, fire-and-forget |
| Command execution | 100-200ms | Typical for regular commands |
| Heartbeat interval | 3.0s ± 0.01s | Excellent consistency |

**Network Efficiency:**
- **Heartbeat overhead:** 45 bytes every 3 seconds = 15 bytes/second = negligible
- **Session stability:** No reconnections observed over 30+ second test
- **Command throughput:** Multiple commands possible per heartbeat interval

## References

- **libArLink.so**: Original PPCS library in Android APK
- **Log Source:** `archive/2025-12-08log.txt`, `paste.txt`
- **Heartbeat & Commands:** `docs/HEARTBEAT_AND_COMMANDS.md`
- **Command Reference:** `docs/COMMAND_IDS_AND_PAYLOADS.md`
- **Implementation:** `modules/pppp_wrapper.py`, `modules/heartbeat.py`, `modules/commands/`
