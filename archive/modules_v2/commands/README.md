# Commands Module

High-level command interface for TrailCam Go protocol.

## Overview

The `commands` package provides structured, type-safe access to all camera device commands discovered through log analysis (2025-12-08).

**Key Components:**
- **`command_ids.py`** - Command ID constants and documentation
- **`heartbeat.py`** - Session keep-alive mechanism (cmdId 525)
- **`device_commands.py`** - High-level command wrappers

**Features:**
- Async-first design (compatible with `asyncio`)
- Automatic error handling and recovery
- Comprehensive logging for debugging
- Type hints for IDE support

## Quick Start

### Basic Usage

```python
from modules.commands import HeartbeatManager, DeviceCommands
from modules.commands.command_ids import *

# Initialize (after successful PPPP connection)
cmds = DeviceCommands(camera_client)
heartbeat = HeartbeatManager(camera_client, interval_sec=3.0)

# Login
await cmds.login(username="admin", password="admin")

# Start heartbeat (critical for session stability)
await heartbeat.start()

# Get device info
info = await cmds.get_device_info(token=session_token)
print(f"Battery: {info['batPercent']}%")

# Start streaming
await cmds.start_av_stream(token=session_token)

# Get all media
media = await cmds.get_all_media_files(token=session_token)
for file in media:
    print(f"File: {file['mediaId']}, Type: {file['fileType']}")

# Stop streaming
await cmds.stop_av_stream(token=session_token)

# Stop heartbeat (on disconnect)
await heartbeat.stop()
```

## Module Details

### command_ids.py

Defines all command IDs and constants from log analysis:

```python
from modules.commands.command_ids import (
    CMD_LOGIN,              # 0 - Authentication
    CMD_START_AV,           # 258 - Start streaming
    CMD_STOP_AV,            # 259 - Stop streaming
    CMD_GET_DEV_INFO,       # 512 - Get device configuration
    CMD_HEARTBEAT,          # 525 - Keep-alive (every 3s)
    CMD_GET_MEDIA_LIST,     # 768 - Get media files
    HEARTBEAT_INTERVAL_SEC, # 3.0 - Default interval
    get_command_name,       # Utility function
)

# Get human-readable name
name = get_command_name(525)  # Returns "HEARTBEAT"
```

### heartbeat.py

Automated session keep-alive mechanism.

**Why Heartbeat?**
- UDP sessions timeout without periodic traffic
- NAT/firewall may close inactive connections
- Observed in logs: cmdId 525 every 3.0 seconds
- Critical for maintaining long-lived sessions

**Usage:**

```python
from modules.commands.heartbeat import HeartbeatManager
from modules.commands.command_ids import HEARTBEAT_INTERVAL_SEC

# Create heartbeat manager
heartbeat = HeartbeatManager(
    camera_client=camera_client,
    interval_sec=HEARTBEAT_INTERVAL_SEC,  # Default: 3.0
    logger=logger  # Optional
)

# Start (run indefinitely in background)
await heartbeat.start()

# Monitor status
if heartbeat.is_running:
    print(f"Sent {heartbeat.heartbeat_count} heartbeats")
    print(f"Last heartbeat: {heartbeat.seconds_since_last_heartbeat}s ago")

# Stop (on disconnect)
await heartbeat.stop()
```

**Key Properties:**
- Runs in background async task
- Non-blocking (doesn't wait for responses)
- Automatic failure recovery
- Stops after 5 consecutive failures

**Log Output:**
```
[INFO] [HEARTBEAT] Start join heart beat thread
[DEBUG] [HEARTBEAT] sendCommand:{"cmdId":525}, seq:65537
[DEBUG] [HEARTBEAT] Send cmd to dev complete, len:45
...
[INFO] [HEARTBEAT] heart beat thread joined
```

### device_commands.py

High-level wrapper for device operations.

**Available Commands:**

#### login()
Authenticate with device:
```python
await cmds.login(
    username="admin",           # Default
    password="admin",           # Default
    need_video=0,              # 0=no, 1=yes
    need_audio=0,              # 0=no, 1=yes
    support_heartbeat=True     # Enable keep-alive
)
```

#### get_device_info()
Retrieve device configuration (~3KB response):
```python
info = await cmds.get_device_info(token=session_token)

print(info["modelName"])          # "KJK230"
print(info["batPercent"])         # 85 (0-100)
print(info["sdFreeMB"])           # Free space
print(info["capabilities"])       # Feature flags
```

#### start_av_stream() / stop_av_stream()
Control media streaming:
```python
await cmds.start_av_stream(token=session_token)
# ... capture stream data ...
await cmds.stop_av_stream(token=session_token)
```

#### get_media_list() / get_all_media_files()
Retrieve media with automatic pagination:
```python
# Single page
response = await cmds.get_media_list(
    token=session_token,
    page_no=0,
    items_per_page=45
)

# All files (auto-paginate)
media = await cmds.get_all_media_files(
    token=session_token,
    items_per_page=45
)

for file in media:
    print(f"ID: {file['mediaId']}, "
          f"Type: {'photo' if file['fileType']==0 else 'video'}, "
          f"Time: {file['mediaTime']}")
```

## Error Handling

### Common Patterns

**Timeout Handling:**
```python
import asyncio

try:
    info = await asyncio.wait_for(
        cmds.get_device_info(token=token),
        timeout=15.0  # 15 seconds for large response
    )
except asyncio.TimeoutError:
    logger.error("Device info retrieval timed out")
    # Reconnect and retry
```

**Error Code Checking:**
```python
response = await cmds.login(username="admin", password="admin")

if response.get("errorCode") != 0:
    error_code = response.get("errorCode", -1)
    logger.error(f"Login failed: error code {error_code}")
    raise LoginError(f"Error {error_code}")
```

**Heartbeat Failure Handling:**
```python
if not heartbeat.is_running:
    logger.warning("Heartbeat stopped, attempting reconnect")
    await reconnect_and_login()
    await heartbeat.start()
```

### Error Recovery Strategy

1. **Transient Errors (timeout, send failure):**
   - Retry after 1-2 seconds
   - Max 3 retries before giving up

2. **Authentication Errors:**
   - Check credentials
   - Re-login if token expired
   - Don't retry indefinitely

3. **Heartbeat Failures:**
   - Count consecutive failures
   - Stop after 5 failures
   - Trigger reconnection sequence
   - Restart heartbeat after re-login

4. **Network Errors:**
   - Check connectivity
   - Verify device is accessible
   - Consider longer timeout for poor networks

## Testing

### Unit Tests

**Test Imports:**
```bash
python3 -c "from modules.commands import HeartbeatManager, DeviceCommands; print('OK')"
```

**Test Command IDs:**
```python
from modules.commands.command_ids import (
    CMD_HEARTBEAT, HEARTBEAT_INTERVAL_SEC, get_command_name
)

assert CMD_HEARTBEAT == 525
assert HEARTBEAT_INTERVAL_SEC == 3.0
assert get_command_name(525) == "HEARTBEAT"
print("Command ID tests passed")
```

### Integration Tests

**Heartbeat Timing Test:**
```python
import time
import asyncio

async def test_heartbeat_interval():
    heartbeat = HeartbeatManager(camera_client, interval_sec=3.0)
    await heartbeat.start()
    
    times = []
    for i in range(5):
        await asyncio.sleep(3.0)
        times.append(time.time())
    
    await heartbeat.stop()
    
    intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
    avg_interval = sum(intervals) / len(intervals)
    
    assert 2.95 < avg_interval < 3.05, f"Bad interval: {avg_interval}"
    print(f"Heartbeat interval OK: {avg_interval:.3f}s")

asyncio.run(test_heartbeat_interval())
```

**Command Execution Test:**
```python
async def test_login_logout():
    cmds = DeviceCommands(camera_client)
    
    # Login
    response = await cmds.login(username="admin", password="admin")
    assert response["errorCode"] == 0, "Login failed"
    
    # Get device info
    info = await cmds.get_device_info(token=session_token)
    assert "modelName" in info, "Missing device info"
    
    print("Login/logout test passed")

asyncio.run(test_login_logout())
```

## Performance Tips

1. **Heartbeat Efficiency:**
   - Minimal payload (~14 bytes JSON)
   - Fire-and-forget (no response expected)
   - Overhead: ~15 bytes/sec

2. **Command Batching:**
   - Don't spam commands
   - Wait for response before next command
   - Parallel commands possible with multiple connections

3. **Media List Pagination:**
   - Larger page sizes (45) = fewer requests
   - Smaller pages (20) = faster responses on slow networks
   - Cache results to avoid re-querying

4. **Timeout Tuning:**
   - Local network: 5-10 seconds
   - Remote (relay): 15-20 seconds
   - Large responses: Up to 30 seconds

## Related Documentation

- **Command Specifications:** `docs/COMMAND_IDS_AND_PAYLOADS.md`
- **Session Management:** `docs/HEARTBEAT_AND_COMMANDS.md`
- **Architecture:** `docs/ARCHITECTURE.md`
- **Protocol Details:** `docs/PROTOCOL_ANALYSIS.md`

## Contributing

When adding new commands:

1. Add constant to `command_ids.py`
2. Add docstring with payload structure
3. Implement wrapper in `device_commands.py`
4. Add log example from capture
5. Update `docs/COMMAND_IDS_AND_PAYLOADS.md`
6. Add unit test to `tests/test_commands.py`

## References

- **Log Source:** 2025-12-08 paste.txt
- **PPPP Protocol:** `docs/PROTOCOL_ANALYSIS.md`
- **Implementation Details:** Individual module docstrings
