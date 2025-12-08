# Archive: Resolved Issues & Legacy Documentation

This directory contains resolved issue documentation and legacy implementation notes.

## Contents

- **FIXES_ISSUE_20.md**: UDP Login connection timeout (RESOLVED)
  - Key insight: Source port binding mechanism
  - Status: Integrated into modules/camera_client.py

- **ISSUE_16_FIX.md**: UDP Connection Stability
  - Status: Resolved

- **ISSUE_18_FIX.md**: BLE Race Condition
  - Status: Integrated into modules/ble_token_listener.py

- **ISSUE_19_FIX.md**: Token Extraction Timeout
  - Status: Integrated (superceded by ISSUE_20)

- **CAMERA_CLIENT_IMPROVEMENTS.md**: Planned improvements for Camera Client
  - Status: Mostly integrated or superseded by recent fixes.

## When to Use

These documents are useful for:
1. Understanding historical problem-solving approach
2. Debugging similar issues in future
3. Reference for protocol reverse-engineering methodology

For current implementation details, see:
- `docs/PROTOCOL_ANALYSIS.md` (protocol spec)
- `docs/ARCHITECTURE.md` (system design)
- Module docstrings in `modules/`
