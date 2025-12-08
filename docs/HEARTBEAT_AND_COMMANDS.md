# Heartbeat and Command Protocol

This document details the command-level protocol observed in the 2025-12-08 application log analysis. It complements the lower-level PPPP protocol documented in `PROTOCOL_ANALYSIS.md`.

## Overview

After successful PPPP/Artemis login, the application maintains the UDP session through periodic heartbeat packets and sends structured JSON commands for device control.

**Key Findings:**
- Commands use JSON payloads with a `cmdId` field
- Heartbeat mechanism (cmdId 525) runs every ~3 seconds
- Session remains stable for extended periods (>30 seconds observed)
- Command responses include status codes and error messages

## Session Management

### Heartbeat Mechanism (cmdId 525)

**Purpose:** Keep UDP session alive and prevent NAT/firewall timeouts

**Interval:** ~3.0 seconds (observed: 18:34:05, 08, 11, 14, 17, 20, ...)

**Payload Structure:**
```json
{"cmdId": 525}
```

**Packet Size:** 45 bytes total (including PPPP wrapper)

**Log Evidence:**
```
[2025-12-08 18:34:05.526][WARN] sendCommand:{"cmdId":525}, seq:65537
[2025-12-08 18:34:05.529][INFO] Send cmd to dev complete, len:45
[2025-12-08 18:34:08.534][WARN] sendCommand:{"cmdId":525}, seq:65538
[2025-12-08 18:34:08.536][INFO] Send cmd to dev complete, len:45
[2025-12-08 18:34:11.544][WARN] sendCommand:{"cmdId":525}, seq:65539
```

**Implementation Notes:**
- Starts after successful login (when `supportHeartBeat: true`)
- Runs in background thread/task
- No response expected (fire-and-forget)
- Failure to send heartbeat can result in session timeout

### Sequence Numbers

The log shows two types of sequence tracking:

1. **PPPP Sequence (Transport Layer):** Increments with every packet
2. **Command Sequence (Application Layer):** Used in heartbeat and commands
   - Heartbeat seq starts at 65537 (0x10001)
   - Regular commands use lower sequence range (1, 2, 3, ...)

## Command Protocol

### General Command Structure

All commands follow a common JSON structure:

```json
{
    "cmdId": <integer>,
    // Additional command-specific fields
    "token": <optional session token>
}
```

**Response Structure:**
```json
{
    "cmdId": <echoed command ID>,
    "result": <0 for success, non-zero for error>,
    "errorMsg": "Success" | <error description>,
    // Command-specific response data
}
```

## Command Catalog

### CMD_LOGIN (0) - Device Authentication

**Direction:** Client → Camera

**Payload:**
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

**Parameters:**
- `usrName`: Login username (typically "admin")
- `password`: Login password (typically "admin")
- `needVideo`: Request video stream (0=no, 1=yes)
- `needAudio`: Request audio stream (0=no, 1=yes)
- `utcTime`: Current Unix timestamp
- `supportHeartBeat`: Enable heartbeat mechanism

**Response:**
```json
{
    "errorCode": 0,  // 0 = success
    "cmdId": 0
}
```

**Log Evidence:**
```
[2025-12-08 18:34:02.514] EC_Login, uid:LBCS-000000-CCCJJ, usrName:admin, password:admin
[2025-12-08 18:34:03.035] EC_OnLoginResult, handle:0, errorCode:0, seq:1
```

### CMD_GET_DEV_INFO (512) - Device Configuration

**Direction:** Client → Camera

**Payload:**
```json
{
    "cmdId": 512,
    "token": <session_token>
}
```

**Response:** Large JSON object (~3KB) containing:
- `devId`: Unique device identifier
- `fwVerName`, `fwVerCode`: Firmware version
- `bleVerName`: Bluetooth firmware version
- `modelName`: Camera model (e.g., "KJK230")
- `productId`: Product identifier
- `customName`: User-assigned name
- `batPercent`: Battery percentage (0-100)
- `isCharging`: Charging status (0/1)
- `sdTotalMB`, `sdFreeMB`: SD card capacity
- `workMode`: Operating mode
- `picResolution`, `videoResolution`: Capture settings
- `capabilities`: Device feature flags

**Fragmentation:**
The response is typically fragmented across multiple UDP packets:
- First fragment: 1024 bytes
- Second fragment: 1024 bytes  
- Third fragment: 1024 bytes
- Final fragment: ~21 bytes

**Total Size:** ~3093 bytes

### CMD_START_AV (258) - Start Streaming

**Direction:** Client → Camera

**Payload:**
```json
{
    "cmdId": 258,
    "token": 143435880
}
```

**Response:**
```json
{
    "errorMsg": "Success",
    "result": 0,
    "cmdId": 258
}
```

**Log Evidence:**
```
[2025-12-08 18:34:31.917] EC_SendCommand, handle:0, command:{"cmdId":258}
[2025-12-08 18:34:31.921] Start send cmd to dev, len:65
```

### CMD_STOP_AV (259) - Stop Streaming

**Direction:** Client → Camera

**Payload:**
```json
{
    "cmdId": 259,
    "token": <session_token>
}
```

**Response:** Similar to START_AV

### CMD_GET_MEDIA_LIST (768) - Retrieve Media Files

**Direction:** Client → Camera

**Payload:**
```json
{
    "cmdId": 768,
    "itemCntPerPage": 45,
    "pageNo": 0,
    "token": 143435880
}
```

**Parameters:**
- `itemCntPerPage`: Number of items per page (default: 45)
- `pageNo`: Page number (0-based)
- `token`: Session token

**Response:**
```json
{
    "mediaFiles": [
        {
            "fileType": 0,           // 0=photo, 1=video
            "mediaDirNum": 100,
            "mediaNum": 225,
            "durationMs": 0,         // Video duration (0 for photos)
            "mediaId": 2444585535,
            "mediaTime": 1765218704  // Unix timestamp
        },
        // ... more files
    ],
    "cnt": 45,                      // Items in this page
    "pageNo": 0,                    // Current page
    "getMediaListRet": 0,           // Status code
    "errorMsg": "Success",
    "result": 0,
    "cmdId": 768
}
```

**Pagination:**
To retrieve all media files, increment `pageNo` until `mediaFiles` array is empty or contains fewer items than `itemCntPerPage`.

## LAN Connection Specifics

### Port Handling in LAN Mode

When the camera is on the local network (LAN/AP mode), the connection follows a simplified pattern:

**Observed Behavior (from 2025-12-08 log):**
```
[2025-12-08 18:34:02.519] Start lan connect to:LBCS-000000-CCCJJ, connectType:1
[2025-12-08 18:34:02.520] Start connect by lan, port:35281
[2025-12-08 18:34:02.879] Lan connect to remote success, mode:P2P, cost time:0,
                          localAddr:(192.168.43.1:35281),
                          remoteAddr:(192.168.43.1:40611)
[2025-12-08 18:34:02.883] LAN connect wait ACK success
[2025-12-08 18:34:02.892] lan connect success
```

**Key Details:**
- **Local Port:** Ephemeral (OS-assigned, e.g., 35281)
- **Remote Port:** 40611 (camera's primary LAN port)
- **Connection Time:** <1 second ("cost time:0")
- **Mode:** Direct LAN-P2P (no relay server needed)

**Port Priority:**
Based on log analysis, the camera primarily listens on:
1. **40611** (PRIMARY - observed in logs)
2. 32100 (secondary)
3. 32108 (fallback)
4. 10000, 80, 57743 (additional fallbacks)

### Session Stability

The log shows a stable session over an extended period:
- Login: 18:34:02
- Heartbeat: 18:34:05, 08, 11, 14, 17, 20, ...
- Commands: 18:34:31 (29 seconds later)

**Stability Factors:**
- Heartbeat prevents UDP timeout
- Same local port used throughout session
- No reconnection attempts needed
- Commands continue to use initial connection

## Implementation Guidelines

### 1. Heartbeat Management

```python
from modules.commands import HeartbeatManager

# After successful login:
heartbeat = HeartbeatManager(camera_client, interval_sec=3.0)
await heartbeat.start()

# On disconnect:
await heartbeat.stop()
```

### 2. Command Execution

```python
from modules.commands import DeviceCommands, CMD_GET_DEV_INFO

commands = DeviceCommands(camera_client)

# Login
await commands.login(username="admin", password="admin")

# Get device info
info = await commands.get_device_info(token=session_token)
print(f"Battery: {info['batPercent']}%")

# Start streaming
await commands.start_av_stream(token=session_token)
```

### 3. Media Retrieval

```python
# Get all media files with pagination
media_files = await commands.get_all_media_files(
    token=session_token,
    items_per_page=45
)

for media in media_files:
    file_type = "photo" if media["fileType"] == 0 else "video"
    print(f"{file_type}: {media['mediaId']} at {media['mediaTime']}")
```

## Error Handling

### Common Error Codes

| errorCode | Meaning | Recovery |
|-----------|---------|----------|
| 0 | Success | - |
| -1 | Generic failure | Retry with backoff |
| -2 | Authentication failed | Re-login |
| -3 | Timeout | Check connection, retry |
| -4 | Invalid parameter | Fix payload structure |

### Heartbeat Failures

If heartbeat fails repeatedly (>5 consecutive failures):
1. Stop heartbeat thread
2. Check UDP connection status
3. Attempt reconnection
4. Re-authenticate if necessary
5. Restart heartbeat after successful login

## Performance Metrics

**Observed Timings (LAN Mode):**
- Connection establishment: <1 second
- Login response: ~520ms
- Device info response: ~1.2 seconds (due to fragmentation)
- Heartbeat interval: 3 seconds
- Command round-trip: ~100-200ms

**Network Characteristics:**
- Protocol: UDP
- No TCP overhead
- Direct LAN connection (no Internet routing)
- Minimal latency in local network

## References

- **Log Source:** `archive/2025-12-08log.txt` and `paste.txt`
- **Connection Manager:** `modules/connection_manager.py`
- **Command Implementation:** `modules/commands/`
- **Lower-Level Protocol:** `docs/PROTOCOL_ANALYSIS.md`
