"""Command ID constants extracted from protocol log analysis.

These command IDs were observed in the 2025-12-08 application log (paste.txt)
and match the Android TrailCam Go app's command structure.

Reference: archive/2025-12-08log.txt and paste.txt
"""

# Authentication & Session
CMD_LOGIN = 0
"""Device login command.

Payload structure (from log):
{
    "cmdId": 0,
    "usrName": "admin",
    "password": "admin",
    "needVideo": 0,
    "needAudio": 0,
    "utcTime": 1765218842,
    "supportHeartBeat": true
}
"""

# Audio/Video Control
CMD_START_AV = 258
"""Start audio/video stream.

Observed in log: {"cmdId":258,"token":143435880}
Response: {"errorMsg":"Success","result":0,"cmdId":258}
"""

CMD_STOP_AV = 259
"""Stop audio/video stream.

Observed in log: {"cmdId":259,"token":143435880}
Response: {"errorMsg":"Success","result":0,"cmdId":259}
"""

# Device Information & Configuration
CMD_GET_DEV_INFO = 512
"""Get device configuration and status.

Returns comprehensive device info including:
- devId, fwVerName, fwVerCode, bleVerName
- modelName, productId, customName
- battery status (batPercent, isCharging)
- SD card status (sdTotalMB, sdFreeMB)
- settings (workMode, picResolution, videoResolution)
- capabilities object

Observed payload size: ~3089 bytes (fragmented across 3x1024 + 21 bytes)
"""

# Session Management
CMD_HEARTBEAT = 525
"""Keep-alive heartbeat command.

Critical findings from log analysis:
- Sent every ~3 seconds (18:34:05, 08, 11, 14, 17, 20, ...)
- Minimal payload: {"cmdId":525}
- Packet size: 45 bytes
- Purpose: Keep UDP session alive, prevent NAT/firewall timeouts

Example log sequence:
[2025-12-08 18:34:05.526][WARN] sendCommand:{"cmdId":525}, seq:65537
[2025-12-08 18:34:08.534][WARN] sendCommand:{"cmdId":525}, seq:65538
[2025-12-08 18:34:11.544][WARN] sendCommand:{"cmdId":525}, seq:65539

Interval: ~3.0 seconds
"""

HEARTBEAT_INTERVAL_SEC = 3.0
"""Default heartbeat interval in seconds (from log observation)."""

# Media Management
CMD_GET_MEDIA_LIST = 768
"""Get list of media files (photos/videos) from camera.

Payload structure:
{
    "cmdId": 768,
    "itemCntPerPage": 45,
    "pageNo": 0,
    "token": 143435880
}

Response contains:
{
    "mediaFiles": [
        {
            "fileType": 0,           # 0=photo, 1=video
            "mediaDirNum": 100,
            "mediaNum": 225,
            "durationMs": 0,
            "mediaId": 2444585535,
            "mediaTime": 1765218704  # Unix timestamp
        },
        ...
    ],
    "cnt": 45,
    "pageNo": 0,
    "getMediaListRet": 0,
    "errorMsg": "Success",
    "result": 0,
    "cmdId": 768
}
"""

# Command ID to name mapping for logging
COMMAND_NAMES = {
    CMD_LOGIN: "LOGIN",
    CMD_START_AV: "START_AV",
    CMD_STOP_AV: "STOP_AV",
    CMD_GET_DEV_INFO: "GET_DEV_INFO",
    CMD_HEARTBEAT: "HEARTBEAT",
    CMD_GET_MEDIA_LIST: "GET_MEDIA_LIST",
}


def get_command_name(cmd_id: int) -> str:
    """Get human-readable name for command ID.
    
    Args:
        cmd_id: Numeric command ID
        
    Returns:
        Command name or f"UNKNOWN_{cmd_id}"
    """
    return COMMAND_NAMES.get(cmd_id, f"UNKNOWN_{cmd_id}")
