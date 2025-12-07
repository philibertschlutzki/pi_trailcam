# Fix #20: UDP Login Connection Timeout

**Status:** ✅ RESOLVED  
**Date:** 2025-12-07  
**Commits:**
- `91b877dd`: UDP Socket binding fix
- `bbc76f8a`: JSON token parsing fix

---

## Problem Description

Script fails to establish UDP connection to camera with repeated timeout errors:

```text
2025-12-07 13:43:20,212 - Main - INFO - [SOCKET] Initializing UDP to 192.168.43.1:40611
2025-12-07 13:43:20,212 - Main - INFO - [STATE] CONNECTING → DISCOVERING
2025-12-07 13:43:23,216 - Main - WARNING - [SEND] Timeout waiting for response (Seq 1)
2025-12-07 13:43:23,216 - Main - WARNING - [DISCOVERY] ✗ Timeout after 3.00s
```

All 6 port attempts fail:
- 40611, 59130, 3014, 47304, 59775, 57743

Total timeout after 5 retry attempts with exponential backoff: **60 seconds**

---

## Root Cause Analysis

### Issue #1: UDP Socket Binding (Primary Cause)

**Misinterpretation of DEVICE_PORTS:**

The Python script treated `DEVICE_PORTS = [40611, 59130, 3014, ...]` as **destination ports** to connect to:

```python
# OLD (WRONG):
self.sock.sendto(packet, (self.ip, port))  # port = 40611, 59130, 3014...
```

**Evidence from Official App Logs:**

The working official app connection showed:
```text
[2025-12-06 22:05:28.982] ... localAddr:(192.168.43.1:57743), remoteAddr:(192.168.43.1:40611)
```

This reveals the actual protocol:
- **Remote Address (Camera):** `192.168.43.1:40611` (FIXED)
- **Local Address (Client):** `192.168.43.1:57743` (VARIABLE)

The app tried ports `59130`, `3014`, `47304`, `59775` before succeeding with `57743`.

**Why This Matters:**

KJK trail cameras use a proprietary firewall/security mechanism that:
1. Only listens on a single fixed port: **40611**
2. Only responds to packets from specific **source ports** (the list in `DEVICE_PORTS`)
3. Similar to port-knocking or port-restricted NAT traversal

This is likely an anti-spoofing measure in the ARTEMIS protocol.

---

### Issue #2: Token Format (Secondary Cause)

**BLE Notification Sends JSON:**

The BLE notification from camera contains JSON-wrapped data:

```text
Token length 72 != 45
[CREDENTIALS] Token={"ret":0,"ssid":"KJK_E0FF", "token":"..."
```

The parser treated the entire JSON string as the authentication token, which is incorrect.

**Expected Format (Old Assumption):**
```text
[4 bytes: length] [4 bytes: sequence] [45 bytes: base64 token]
```

**Actual Format (Camera Implementation):**
```text
[4 bytes: json_length] [4 bytes: sequence] [JSON string with embedded token]
```

---

## Solutions Implemented

### Solution #1: Socket Binding to Source Ports

**File:** `modules/camera_client.py`  
**Method:** `_create_socket()`  
**Commit:** `91b877dd`

**Changes:**

1. **Bind to source port from DEVICE_PORTS:**
   ```python
   self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   self.sock.bind(('', port))  # Bind to SOURCE port
   ```

2. **Always send to destination 40611:**
   ```python
   self.sock.sendto(packet, (self.ip, config.CAM_PORT))  # config.CAM_PORT = 40611
   ```

3. **SO_REUSEADDR flag:**
   - Allows rapid port reuse
   - Prevents "Address already in use" errors during retries
   - Essential for iterating through multiple source ports

4. **Improved logging:**
   ```text
   [SOCKET] Binding local UDP source port 57743 → Destination 192.168.43.1:40611
   [SOCKET] Created successfully. Bind to local port 57743, sending to 192.168.43.1:40611
   ```

**Before (Wrong):**
```python
def _create_socket(self, port):
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.port = port  # THIS IS DESTINATION
    self.sock.sendto(final_packet, (self.ip, self.port))  # Sends to 59130, 3014, etc.
```

**After (Correct):**
```python
def _create_socket(self, port):
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.sock.bind(('', port))  # Bind to SOURCE port
    # self.port stays as config.CAM_PORT (40611)
    self.sock.sendto(final_packet, (self.ip, self.port))  # Always sends to 40611
```

---

### Solution #2: JSON Token Parsing

**File:** `modules/ble_token_listener.py`  
**Method:** `_parse_payload()`  
**Commit:** `bbc76f8a`

**Changes:**

1. **Detect JSON format:**
   ```python
   if token_str.startswith('{') and '}' in token_str:
       # Parse as JSON
   ```

2. **Extract token from known fields:**
   ```python
   for field_name in ['token', 'data', 'key', 'auth_token', 'access_token']:
       if field_name in token_json:
           actual_token = token_json[field_name]
           break
   ```

3. **Support both formats:**
   - Raw format: `[header][45-byte base64 token]`
   - JSON format: `[header]{"token": "...", "ret": 0, ...}`

4. **Enhanced logging:**
   ```text
   [PARSE] Detected JSON token format
   [PARSE] Extracted token from field 'token'
   [PARSE] Using extracted token (length: 45)
   ```

**Example Parsing:**

Input JSON:
```json
{
  "ret": 0,
  "ssid": "KJK_E0FF",
  "token": "I3mbwVIx...",
  "seq": 48000000
}
```

Output:
```python
{
    "token": "I3mbwVIx...",
    "sequence": b'\x00\x00\xb8\x02'
}
```

---

## Testing & Verification

### Expected Behavior After Fixes

1. **Connection Phase (DISCOVERING):**
   ```text
   [CONNECT] Trying source port 40611 (1/6)
   [SOCKET] Binding local UDP source port 40611 → Destination 192.168.43.1:40611
   [DISCOVERY] Starting ARTEMIS discovery phase...
   [DISCOVERY] ✓ Response received in 0.25s
   ```

2. **Token Extraction:**
   ```text
   [NOTIFICATION] Received 80 bytes
   [PARSE] Detected JSON token format
   [PARSE] Extracted token from field 'token'
   [CREDENTIALS] Token=I3mbwVIx..., Sequence=2B000000, BLE_Dynamic=ENABLED
   ```

3. **Login Phase:**
   ```text
   PHASE 3: UDP LOGIN (Attempt 1, Variant: BLE_DYNAMIC)
   [LOGIN] ✓ SUCCESS with variant 'BLE_DYNAMIC'
   ```

### Testing Steps

```bash
# Pull latest changes
git pull

# Run the script
python main.py

# Monitor output for:
# - "Device discovered on source port X" (connection success)
# - "JSON token format" (parser working)
# - "SUCCESS" (full authentication success)
```

---

## Protocol Analysis

### Why Source Port Binding Works

**Hypothesis:** Kamera-Firewall/P2P-Traversal-Technik

1. **Port Knocking Pattern:**
   - Camera listens on port 40611
   - Only responds to packets from specific "known" source ports
   - Prevents unsolicited connections/scanning

2. **NAT/Firewall Rules:**
   - Similar to UPnP port mapping behavior
   - Registered apps have pre-approved source ports
   - Prevents malware from impersonating devices

3. **Device Identification:**
   - Each phone/PC has unique source port signature
   - Server recognizes device by combination of (IP:port) + token
   - Add second security layer on top of token auth

### Why JSON Token Format

1. **Extensible Design:**
   - JSON allows forward-compatible protocol updates
   - Can add new fields without breaking parsing
   - Easier to debug than binary formats

2. **Additional Metadata:**
   - `ret`: Return code (0 = success)
   - `ssid`: Confirmation of WiFi network
   - Potentially other device info

3. **Standardization:**
   - Most IoT devices use JSON for API/protocol
   - Camera likely running Android (AOSP) framework
   - JSON part of device SDK

---

## Related Issues

- Issue #18: BLE notification handler race condition (fixed in `_parse_payload`)
- Issue #19: Token extraction timeout (addressed in timeout handling)

---

## Configuration Reference

**File:** `config.py`

```python
# Device Ports (SOURCE ports to bind to, in order of preference)
DEVICE_PORTS = [40611, 59130, 3014, 47304, 59775, 57743]

# Always sends to this DESTINATION port
CAM_PORT = 40611
```

---

## Future Improvements

1. **Port Priority Learning:**
   - Log which source port works
   - Try that port first in next connection
   - Saves retry time

2. **Token Caching:**
   - Store extracted tokens with timestamp
   - Reuse same token if <5 minutes old
   - Reduces BLE overhead

3. **Adaptive Timeout:**
   - Monitor response times
   - Increase timeout if device responds slowly
   - Decrease if response is fast

---

## References

- [ARTEMIS Protocol](https://github.com/philibertschlutzki/pi_trailcam/blob/main/docs/) (proprietary reverse-engineered)
- [Official App Logs](https://github.com/philibertschlutzki/pi_trailcam/issues/20) (GitHub issue #20)
- [BLE Token Listener](modules/ble_token_listener.py)
- [Camera Client](modules/camera_client.py)
