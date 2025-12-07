# Authentication Variant Testing - MYSTERY_09_01

## Problem Summary

Issue #7 showed that all 6 hardcoded authentication variants failed with consistent UDP timeouts on port 40611.

## Root Cause Discovery

Analysis of successful tcpdump captures (`tcpdump_1800_connect.log`) revealed the actual authentication bytes used in a successful login:

```
ARTEMIS Protocol Payload Structure:
[00-07] Magic:     415254454d495300 = "ARTEMIS\0"
[08-11] Type/Ver:  02000000
[12-15] MYSTERY:   09000100  ← THE KEY DIFFERENCE!
[16-19] Length:    19000000
[20-...] AuthToken: MzlB36X/IVo8ZzI5rG9j1w==
```

## The Fix: MYSTERY_09_01

### New Bytes Discovered

The authentication variant that actually works uses these mystery bytes (position [12:16]):
- **Hex:** `09 00 01 00`
- **Interpretation:** 
  - `0x09` = Command/Message Type (possibly LOGIN)
  - `0x00` = Reserved/Padding
  - `0x01` = Subtype or Message ID
  - `0x00` = Reserved/Padding

### Byte Comparison

| Variant | Bytes [12:16] | Status |
|---------|---------------|--------|
| SMARTPHONE_DUMP | `2b 00 2d 00` | ✗ Failed |
| ORIGINAL | `02 00 01 00` | ✗ Failed |
| MYSTERY_2B_ONLY | `2b 00 00 00` | ✗ Failed |
| MYSTERY_2D_ONLY | `2d 00 00 00` | ✗ Failed |
| NO_MYSTERY | (none) | ✗ Failed |
| SEQUENCE_VARIANT | `03 00 04 00` | ✗ Failed |
| **MYSTERY_09_01** | **`09 00 01 00`** | **✓ Working** |

## Implementation Changes

### 1. `modules/camera_client.py`

**Added:** MYSTERY_VARIANTS dictionary
```python
MYSTERY_VARIANTS = {
    'MYSTERY_09_01': bytes([0x09, 0x00, 0x01, 0x00]),      # ✓ From tcpdump
    'SMARTPHONE_DUMP': bytes([0x2b, 0x00, 0x2d, 0x00]),   # Legacy
    'ORIGINAL': bytes([0x02, 0x00, 0x01, 0x00]),          # Legacy
    'MYSTERY_2B_ONLY': bytes([0x2b, 0x00, 0x00, 0x00]),   # Legacy
    'MYSTERY_2D_ONLY': bytes([0x2d, 0x00, 0x00, 0x00]),   # Legacy
    'SEQUENCE_VARIANT': bytes([0x03, 0x00, 0x04, 0x00]),  # Legacy
}
```

**Updated Methods:**
- `_build_login_payload(variant='MYSTERY_09_01')` - Now accepts variant parameter
- `login(variant='MYSTERY_09_01')` - Now accepts and tests individual variants
- `login_all_variants()` - **NEW:** Tests all variants in order (MYSTERY_09_01 first)

### 2. `main.py`

**Updated:** Changed `camera.login()` to `camera.login_all_variants()`

This will automatically test all authentication variants starting with MYSTERY_09_01.

## How to Test

### Option A: Automatic Testing (Recommended)

Run the main script normally:

```bash
(venv) pi@raspberrypi:~/pi_trailcam $ python3 main.py
```

This will:
1. Wake camera via BLE
2. Extract auth token
3. Connect to camera WiFi
4. **Automatically test all variants in order** with detailed logging

### Option B: Test Single Variant

For debugging, modify main.py to test a specific variant:

```python
# Instead of login_all_variants()
if camera.login(variant='MYSTERY_09_01'):
    logger.info("✓ SUCCESS")
else:
    logger.info("✗ FAILED")
```

### Expected Output

When testing with `login_all_variants()`:

```
======================================================================
STARTE SYSTEMATISCHEN VARIANT-TEST
======================================================================

--- Test 1/7: MYSTERY_09_01 ---
    Mystery Bytes: 09000100
2025-12-07 09:00:00,123 - Main - INFO - >>> PHASE 3: UDP LOGIN (Variant: MYSTERY_09_01)
2025-12-07 09:00:00,125 - Main - INFO - Mystery Bytes [12:16]: 09000100
2025-12-07 09:00:05,200 - Main - INFO - ✓ LOGIN SUCCESSFUL with variant 'MYSTERY_09_01'

✓✓✓ ERFOLG MIT VARIANTE: MYSTERY_09_01 ✓✓✓
```

## Next Investigation Steps

If MYSTERY_09_01 succeeds:
- ✓ Problem solved!
- Document in main README

If MYSTERY_09_01 still fails:
1. Check tcpdump logs more carefully for other successful captures
2. Investigate if these bytes are dynamically generated from BLE token
3. Look for patterns in how bytes change between requests
4. Analyze BLE notifications for challenge-response mechanism

## Files Modified

- `modules/camera_client.py` - Added MYSTERY_VARIANTS, updated login methods
- `main.py` - Updated to use login_all_variants()
- `TESTING_VARIANTS.md` - This documentation

## References

- Issue #7: "Alle Varianten fehlgeschlagen"
- tcpdump Analysis: See commit message for detailed byte analysis
- tcpdump source logs: `tcpdump_1800_connect.log`, `tcpdump_1800_2.log`
