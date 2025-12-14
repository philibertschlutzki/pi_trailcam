# Command IDs and Payload Reference

This document provides a comprehensive reference for all observed command IDs and their payload structures in the TrailCam Go protocol.

**Data Source:** 2025-12-08 application log analysis (`paste.txt`)

## Command ID Overview

| ID | Name | Layer | Direction | Interval | Priority | Status |
|----|------|-------|-----------|----------|----------|--------|
| 0 | LOGIN | Command | C→D | Once/session | Critical | Implemented |
| 258 | START_AV | Command | C→D | On demand | High | Implemented |
| 259 | STOP_AV | Command | C→D | On demand | High | Implemented |
| 512 | GET_DEV_INFO | Command | C→D | On demand | Medium | Implemented |
| 525 | HEARTBEAT | Session | C→D | Every 3s | Critical | Implemented |
| 768 | GET_MEDIA_LIST | Command | C→D | On demand | Medium | Implemented |

---

## Detailed Command Specifications

### 0 - LOGIN (Device Authentication)

**Category:** Authentication / Session Management

**Purpose:** Authenticate with the camera device using default credentials

**Direction:** Client → Device

**Typical Interval:** Once per session (after PPPP discovery)

**Request Payload:**
```json
{
    "cmdId": 0,
    "usrName": "admin",
    "password": "admin",
    "needVideo": 0,
    "needAudio": 0,
    "utcTime": 1765218842,
    "supportHeartBeat": true
}
```

**Request Parameters:**
- `cmdId` (int): Always 0
- `usrName` (string): Username (typically "admin")
- `password` (string): Password (typically "admin")
- `needVideo` (int): Request video stream (0=no, 1=yes)
- `needAudio` (int): Request audio stream (0=no, 1=yes)
- `utcTime` (int): Current Unix timestamp (seconds)
- `supportHeartBeat` (bool): Enable heartbeat mechanism (should be true)

**Response Payload:**
```json
{
    "errorCode": 0,
    "cmdId": 0
}
```

**Response Parameters:**
- `errorCode` (int): 0 = success, non-zero = error (see error codes section)
- `cmdId` (int): Echoed command ID

**Success Criteria:**
- `errorCode == 0`
- Response received within 10 seconds

**Log Example:**
```
[2025-12-08 18:34:02.514] EC_Login, uid:LBCS-000000-CCCJJ, usrName:admin, password:admin
[2025-12-08 18:34:03.035] EC_OnLoginResult, handle:0, errorCode:0, seq:1
```

**Error Handling:**
- If `errorCode != 0`: Authentication failed
  - Check credentials
  - Verify device is not in locked mode
  - Retry after 1 second backoff
- If timeout: UDP session may be broken
  - Reconnect and retry
  - Check network connectivity

**Notes:**
- After successful login, `HeartbeatManager` should be started
- Session token is not explicitly returned; it's maintained internally
- Default credentials work on factory-reset devices

---

### 258 - START_AV (Start Audio/Video Stream)

**Category:** Media Control / Streaming

**Purpose:** Initiate audio and/or video stream from the camera

**Direction:** Client → Device

**Typical Interval:** On demand (user initiates)

**Prerequisites:** Successful login (errorCode 0 from cmdId 0)

**Request Payload:**
```json
{
    "cmdId": 258,
    "token": 143435880
}
```

**Request Parameters:**
- `cmdId` (int): Always 258
- `token` (int): Session token from login (or derived from session)

**Response Payload:**
```json
{
    "errorMsg": "Success",
    "result": 0,
    "cmdId": 258
}
```

**Response Parameters:**
- `errorMsg` (string): Human-readable result message
- `result` (int): 0 = success, non-zero = error
- `cmdId` (int): Echoed command ID

**Success Criteria:**
- `result == 0`
- `errorMsg == "Success"`
- Response received within 10 seconds

**Log Example:**
```
[2025-12-08 18:34:31.917] EC_SendCommand, handle:0, command:{"cmdId":258}
[2025-12-08 18:34:31.921] Start send cmd to dev, len:65
```

**Error Handling:**
- If `result != 0`: Stream start failed
  - Check device has power and is not overheating
  - Verify SD card is present and has space
  - Retry after 500ms
- If timeout: Device may be busy
  - Wait 2 seconds
  - Retry once
  - If still fails, reconnect

**Notes:**
- Once started, stream data flows on separate UDP port/connection
- This command only initiates the stream; actual media data is handled separately
- Device may only support one stream at a time

---

### 259 - STOP_AV (Stop Audio/Video Stream)

**Category:** Media Control / Streaming

**Purpose:** Terminate audio and/or video stream from the camera

**Direction:** Client → Device

**Typical Interval:** On demand (user stops viewing)

**Prerequisites:** Active stream (previously started with cmdId 258)

**Request Payload:**
```json
{
    "cmdId": 259,
    "token": 143435880
}
```

**Request Parameters:**
- `cmdId` (int): Always 259
- `token` (int): Session token

**Response Payload:**
```json
{
    "errorMsg": "Success",
    "result": 0,
    "cmdId": 259
}
```

**Response Parameters:** (same as START_AV)
- `errorMsg` (string): Human-readable result message
- `result` (int): 0 = success, non-zero = error
- `cmdId` (int): Echoed command ID

**Success Criteria:**
- `result == 0`
- Response received within 10 seconds

**Error Handling:**
- If already stopped: May return error or success (depends on device)
  - Treat as non-critical
  - Log and continue
- If timeout: Stream may have already stopped
  - Assume stopped and continue
  - No reconnection needed

**Notes:**
- Safe to call even if stream is not active
- Ensures clean resource cleanup
- Should be called before disconnect

---

### 512 - GET_DEV_INFO (Device Configuration)

**Category:** Device Management / Information

**Purpose:** Retrieve comprehensive device configuration and status information

**Direction:** Client → Device

**Typical Interval:** On demand (at startup or user request)

**Prerequisites:** Successful login

**Request Payload:**
```json
{
    "cmdId": 512,
    "token": 143435880
}
```

**Request Parameters:**
- `cmdId` (int): Always 512
- `token` (int): Session token

**Response Payload (Large - ~3KB):**
```json
{
    "devId": "LBCS-000000-CCCJJ",
    "fwVerName": "2.10.0.22",
    "fwVerCode": 21022,
    "bleVerName": "1.0.5",
    "modelName": "KJK230",
    "productId": 115,
    "customName": "Trail Cam",
    "batPercent": 85,
    "isCharging": 0,
    "sdTotalMB": 32768,
    "sdFreeMB": 8192,
    "workMode": 1,
    "picResolution": "1920x1080",
    "videoResolution": "1920x1080",
    "capabilities": {
        "support_heartbeat": true,
        "support_audio": true,
        "support_video": true,
        "support_night_vision": true
    },
    "errorMsg": "Success",
    "result": 0,
    "cmdId": 512
}
```

**Response Parameters:**
- `devId` (string): Unique device identifier
- `fwVerName` (string): Firmware version (semantic: major.minor.patch.build)
- `fwVerCode` (int): Firmware version code
- `bleVerName` (string): Bluetooth firmware version
- `modelName` (string): Camera model (e.g., "KJK230")
- `productId` (int): Product identifier code
- `customName` (string): User-assigned device name
- `batPercent` (int): Battery level (0-100, -1 if plugged in)
- `isCharging` (int): 0 = not charging, 1 = charging
- `sdTotalMB` (int): SD card total capacity in MB
- `sdFreeMB` (int): SD card free space in MB
- `workMode` (int): Operating mode (1=normal, 2=time-lapse, etc.)
- `picResolution` (string): Photo resolution (e.g., "1920x1080")
- `videoResolution` (string): Video resolution
- `capabilities` (object): Feature support flags
- `errorMsg` (string): Result message
- `result` (int): 0 = success
- `cmdId` (int): Echoed command ID

**Success Criteria:**
- `result == 0`
- Response received within 15 seconds
- Response is typically fragmented across multiple UDP packets

**Response Fragmentation:**
- Fragment 1: ~1024 bytes
- Fragment 2: ~1024 bytes
- Fragment 3: ~1024 bytes
- Fragment 4: ~21 bytes
- **Total:** ~3093 bytes

**Handling Large Responses:**
- Must implement UDP packet reassembly
- Monitor for timeout (15 seconds)
- Log fragment receipt for debugging

**Log Example:**
```
[2025-12-08 18:34:02.501] sendCommand:{"cmdId":512,"token":143435880}
[2025-12-08 18:34:02.613] Recv cmd response data, size:1024
[2025-12-08 18:34:02.625] Recv cmd response data, size:1024
[2025-12-08 18:34:02.637] Recv cmd response data, size:1024
[2025-12-08 18:34:02.649] Recv cmd response data, size:21
```

**Error Handling:**
- If timeout: Device may be busy
  - Retry after 2 seconds
  - Check device status (power, network)
- If incomplete fragments: Reassembly error
  - Discard partial response
  - Retry

**Notes:**
- Response is large; caching recommended to reduce network load
- Good indicator of device health (battery, SD card space)
- Capabilities flags indicate feature support for command filtering

---

### 525 - HEARTBEAT (Keep-Alive)

**Category:** Session Management / Keep-Alive

**Purpose:** Maintain UDP session and prevent NAT/firewall timeouts

**Direction:** Client → Device

**Interval:** Every 3.0 seconds (critical for session stability)

**Typical Timing:** Starts immediately after successful login

**Request Payload (Minimal):**
```json
{"cmdId": 525}
```

**Request Parameters:**
- `cmdId` (int): Always 525

**Response:** None expected (fire-and-forget)

**Packet Characteristics:**
- **Total size:** 45 bytes (including PPPP wrapper)
- **JSON payload:** ~14 bytes
- **PPPP overhead:** ~8 bytes
- **UDP/IP overhead:** ~28 bytes
- **Bandwidth:** 45 bytes × 0.333 Hz = 15 bytes/second ≈ negligible

**Timing Evidence (from 2025-12-08 log):**
```
[18:34:05.526] sendCommand:{"cmdId":525}, seq:65537
[18:34:08.534] sendCommand:{"cmdId":525}, seq:65538  (Δ = 3.008s)
[18:34:11.544] sendCommand:{"cmdId":525}, seq:65539  (Δ = 3.010s)
[18:34:14.555] sendCommand:{"cmdId":525}, seq:65540  (Δ = 3.011s)
```

**Interval Stability:** ±0.01 seconds (±10 milliseconds)

**Critical Properties:**
- **No response expected:** Fire-and-forget mechanism
- **No error checking:** Device processes silently
- **Asynchronous:** Should run in background task/thread
- **Survivable failure:** Missing occasional heartbeats won't break session
- **Critical threshold:** >5 consecutive failures → force reconnection

**Implementation Requirements:**
```python
async def heartbeat_loop():
    while connected:
        await send_command(cmd_id=525, payload=None)
        await asyncio.sleep(3.0)  # Exact 3-second interval
```

**Error Handling:**
- If send fails: Log warning, increment failure counter
- If 5 failures: Stop heartbeat, trigger reconnect
- If send succeeds: Reset failure counter
- Network may drop occasional packets; this is normal

**Importance:**
- **Without heartbeat:** Session timeout after 30-60 seconds (depends on NAT/firewall)
- **With heartbeat:** Session can persist indefinitely
- **LAN mode:** Less critical but still recommended
- **Remote mode:** Essential for relay server connection stability

**Log Output Format:**
```
[TIMESTAMP] sendCommand:{"cmdId":525}, seq:XXXXXX
[TIMESTAMP] Send cmd to dev complete, len:45
```

**Notes:**
- This is the most critical command for session stability
- Should start immediately after successful login
- Must be stopped on session close
- Consider dynamic interval based on network conditions (future enhancement)

---

### 768 - GET_MEDIA_LIST (Media Retrieval)

**Category:** Media Management / File Retrieval

**Purpose:** Retrieve list of recorded photos and videos with metadata

**Direction:** Client → Device

**Typical Interval:** On demand (user browsing media)

**Prerequisites:** Successful login

**Request Payload:**
```json
{
    "cmdId": 768,
    "itemCntPerPage": 45,
    "pageNo": 0,
    "token": 143435880
}
```

**Request Parameters:**
- `cmdId` (int): Always 768
- `itemCntPerPage` (int): Items to return per page (typically 45)
- `pageNo` (int): Page number, 0-based (0 = first page)
- `token` (int): Session token

**Response Payload:**
```json
{
    "mediaFiles": [
        {
            "fileType": 0,
            "mediaDirNum": 100,
            "mediaNum": 225,
            "durationMs": 0,
            "mediaId": 2444585535,
            "mediaTime": 1765218704
        },
        {
            "fileType": 1,
            "mediaDirNum": 100,
            "mediaNum": 226,
            "durationMs": 15000,
            "mediaId": 2444585536,
            "mediaTime": 1765218720
        },
        // ... more media files (up to itemCntPerPage)
    ],
    "cnt": 45,
    "pageNo": 0,
    "getMediaListRet": 0,
    "errorMsg": "Success",
    "result": 0,
    "cmdId": 768
}
```

**Response Parameters:**
- `mediaFiles` (array): Array of media file objects
  - `fileType` (int): 0 = photo, 1 = video
  - `mediaDirNum` (int): Directory number on device
  - `mediaNum` (int): File number within directory
  - `durationMs` (int): Duration in milliseconds (0 for photos)
  - `mediaId` (int): Unique media identifier
  - `mediaTime` (int): Creation time as Unix timestamp
- `cnt` (int): Number of files in this response
- `pageNo` (int): Current page number
- `getMediaListRet` (int): List retrieval status
- `errorMsg` (string): Result message
- `result` (int): 0 = success
- `cmdId` (int): Echoed command ID

**Pagination Logic:**
```python
all_files = []
page_no = 0
while True:
    response = get_media_list(page_no=page_no, items_per_page=45)
    files = response["mediaFiles"]
    if not files:  # Empty response
        break
    all_files.extend(files)
    if len(files) < 45:  # Partial page = last page
        break
    page_no += 1
```

**Success Criteria:**
- `result == 0`
- `mediaFiles` array is present (may be empty)
- Response received within 15 seconds

**Log Example:**
```
[2025-12-08 18:34:28.914] EC_SendCommand, handle:0, command:{"cmdId":768}
[2025-12-08 18:34:29.027] Recv cmd response data, size:2048
[2025-12-08 18:34:29.156] Media list retrieved: 45 files, page 0
```

**Error Handling:**
- If timeout: Device processing large list
  - Increase timeout to 20 seconds for this command
  - Reduce itemCntPerPage to 20 for faster responses
- If empty list: No media on device
  - This is normal on new devices
  - Check SD card is present
- If corruption: Garbled response
  - Reconnect and retry
  - May indicate SD card issue

**Performance Tips:**
- Cache media list if device has stable filesystem
- Reduce `itemCntPerPage` for slower networks (e.g., remote relay mode)
- Request only needed metadata fields (future optimization)
- Use `mediaTime` for sorting and deduplication

**Notes:**
- Response size varies based on number of files
- Typical response: 1-5 KB per page
- Fragmentation possible on slow networks
- `mediaId` is unique per media file (good for tracking)
- `mediaTime` is creation timestamp (useful for chronological sorting)

---

## Error Codes

| Code | Meaning | Recovery |
|------|---------|----------|
| 0 | Success | - |
| -1 | Generic failure | Retry with backoff |
| -2 | Authentication failed | Check credentials, re-login |
| -3 | Timeout | Check network, increase timeout |
| -4 | Invalid parameter | Fix payload, check command ID |
| -5 | Device busy | Wait 1 second, retry |
| -6 | SD card error | Check SD card presence |
| -7 | Low battery | Warn user, consider graceful shutdown |
| -8 | Thermal shutdown | Wait 5 minutes for cooling |
| -9 | Command not supported | Check device capabilities |

## Implementation Reference

See `modules/commands/device_commands.py` for Python implementation examples:

```python
from modules.commands import DeviceCommands

cmds = DeviceCommands(camera_client)

# Login
await cmds.login(username="admin", password="admin")

# Get device info
info = await cmds.get_device_info(token=session_token)
print(f"Battery: {info['batPercent']}%")

# Start streaming
await cmds.start_av_stream(token=session_token)

# Get media with pagination
media = await cmds.get_all_media_files(token=session_token)
for file in media:
    print(f"File ID: {file['mediaId']}, Type: {file['fileType']}")

# Stop streaming
await cmds.stop_av_stream(token=session_token)
```

## Related Documentation

- **Heartbeat Details:** `docs/HEARTBEAT_AND_COMMANDS.md`
- **Protocol Stack:** `docs/PROTOCOL_ANALYSIS.md`
- **Architecture:** `docs/ARCHITECTURE.md`
- **Implementation:** `modules/commands/`
