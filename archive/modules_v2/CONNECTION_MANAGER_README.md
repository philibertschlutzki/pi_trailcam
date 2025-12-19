# Parallel Connection Manager - Usage Guide

## Overview

The `ParallelConnectionManager` is an enhanced connection module inspired by the libArLink.so architecture from the original Android TrailCam Go app. It implements three parallel connection threads (P2P, LAN, Relay) that race to establish a connection with minimal latency.

## Quick Start

```python
from modules.connection_manager import ParallelConnectionManager
import logging

# Setup logging
logger = logging.getLogger("MyApp")

# Create manager
manager = ParallelConnectionManager(
    camera_ip="192.168.1.100",
    destination_ports=(40611, 32100, 32108),
    max_connection_time=30.0,
    logger=logger
)

# Start parallel connection attempts
success, info = manager.connect_parallel(
    enable_p2p=True,     # UDP P2P thread
    enable_lan=True,     # UDP LAN thread
    enable_relay=False   # TCP Relay (not implemented)
)

if success:
    print(f"\u2713 Connected via {info['winning_thread']}")
    print(f"  Local port: {info['port']}")
    print(f"  Target port: {info['destination_port']}")
    print(f"  Time: {info['elapsed_time']:.2f}s")
else:
    print("\u2717 Connection failed")
```

## Constructor Parameters

```python
ParallelConnectionManager(
    camera_ip: str,
    destination_ports: Tuple[int, ...] = (40611, 32100, 32108, 10000, 80, 57743),
    max_connection_time: float = 30.0,
    logger: Optional[logging.Logger] = None
)
```

### Parameters

- **`camera_ip`** (str, required)
  - Target camera IP address
  - Example: `"192.168.1.100"`

- **`destination_ports`** (tuple, default: `(40611, 32100, 32108, 10000, 80, 57743)`)
  - List of ports to try, in order of preference
  - First port in list is primary (will be tried first)
  - If connection fails, next port is automatically tried by each thread
  - Format: `(port1, port2, port3, ...)`

- **`max_connection_time`** (float, default: `30.0`)
  - Maximum seconds to spend attempting connections
  - If all threads fail before timeout, connection fails
  - Example: `30.0` means give up after 30 seconds

- **`logger`** (logging.Logger, optional)
  - Logger instance for debug output
  - If not provided, creates default logger
  - Configure with your application's logger for consistency

## Main Method: `connect_parallel()`

```python
success, info = manager.connect_parallel(
    enable_p2p: bool = True,
    enable_lan: bool = True,
    enable_relay: bool = False
) -> Tuple[bool, Optional[Dict[str, Any]]]
```

### Parameters

- **`enable_p2p`** (bool, default: `True`)
  - Start P2P direct connection thread
  - Uses UDP, fastest for direct device connections
  - Recommended: Always enabled

- **`enable_lan`** (bool, default: `True`)
  - Start LAN direct connection thread
  - Uses UDP over local network
  - Recommended: Always enabled

- **`enable_relay`** (bool, default: `False`)
  - Start TCP relay connection thread
  - Requires relay server configuration
  - Status: Not yet implemented

### Return Value

Returns tuple: `(success: bool, info: dict | None)`

#### On Success (`success == True`):

```python
info = {
    'mode': ConnectionMode.P2P,  # or .LAN, .RELAY
    'port': 56799,               # Local ephemeral port used
    'destination_port': 40611,   # Which port succeeded
    'elapsed_time': 2.34,        # Seconds to establish connection
    'winning_thread': 'p2pConnectThread',  # Which thread won
    'threads_info': {
        'p2pConnectThread': {
            'mode': 'p2p',
            'state': 'success',
            'port': 56799,
            'retries': 1,
            'elapsed': 2.34,
            'error': None
        },
        'lanConnectThread': {
            'mode': 'lan',
            'state': 'cancelled',
            'port': None,
            'retries': 0,
            'elapsed': None,
            'error': None
        },
        'relayConnectThread': {
            'mode': 'relay',
            'state': 'not_started',
            'port': None,
            'retries': 0,
            'elapsed': None,
            'error': None
        }
    }
}
```

#### On Failure (`success == False`):

```python
info = {
    'elapsed_time': 30.01,  # Max timeout reached
    'threads_info': {
        'p2pConnectThread': {
            'mode': 'p2p',
            'state': 'failed',
            'port': 56799,
            'retries': 6,
            'elapsed': 30.0,
            'error': None
        },
        # ... similar for other threads
    }
}
```

### Thread States

- **`pending`**: Thread not yet started
- **`running`**: Thread actively attempting connection
- **`success`**: Connection established successfully
- **`failed`**: All attempts exhausted, connection failed
- **`cancelled`**: Another thread succeeded, this thread was terminated

## Usage Examples

### Example 1: Basic Connection with Default Settings

```python
from modules.connection_manager import ParallelConnectionManager

manager = ParallelConnectionManager(
    camera_ip="192.168.1.100"
)

success, info = manager.connect_parallel()

if success:
    print(f"Connected in {info['elapsed_time']:.2f}s via {info['winning_thread']}")
else:
    print("Connection failed")
```

### Example 2: Custom Port List

```python
# Try specific ports in specific order
manager = ParallelConnectionManager(
    camera_ip="192.168.1.100",
    destination_ports=(40611, 32100),  # Only try these two
    max_connection_time=15.0           # Give up after 15 seconds
)

success, info = manager.connect_parallel()
```

### Example 3: Disable Certain Threads

```python
# Only try P2P (fastest, no relay server needed)
success, info = manager.connect_parallel(
    enable_p2p=True,
    enable_lan=False,    # Skip LAN thread
    enable_relay=False
)
```

### Example 4: Detailed Diagnostics

```python
success, info = manager.connect_parallel()

if success:
    print(f"\u2713 SUCCESS")
    print(f"  Winning thread: {info['winning_thread']}")
    print(f"  Connection mode: {info['mode'].value}")
    print(f"  Local port: {info['port']}")
    print(f"  Target port: {info['destination_port']}")
    print(f"  Total time: {info['elapsed_time']:.2f}s")
else:
    print(f"\u2717 FAILED after {info['elapsed_time']:.2f}s")

# Print all thread stats
for thread_name, thread_info in info['threads_info'].items():
    print(f"\n{thread_name}:")
    print(f"  State: {thread_info['state']}")
    print(f"  Retries: {thread_info['retries']}")
    if thread_info['elapsed']:
        print(f"  Time: {thread_info['elapsed']:.2f}s")
    if thread_info['error']:
        print(f"  Error: {thread_info['error']}")
```

### Example 5: Integration with CameraClient

```python
from modules.camera_client import CameraClient
from modules.connection_manager import ParallelConnectionManager

# Step 1: Establish connection using parallel manager
manager = ParallelConnectionManager(
    camera_ip=camera_ip,
    destination_ports=(40611, 32100, 32108),
    logger=logger
)

success, info = manager.connect_parallel(
    enable_p2p=True,
    enable_lan=True
)

if success:
    logger.info(f"Connected via {info['winning_thread']} in {info['elapsed_time']:.2f}s")
    
    # Step 2: Now use CameraClient with the discovered port
    camera = CameraClient(
        camera_ip=camera_ip,
        source_port=info['port'],  # Reuse successful port
        logger=logger
    )
    
    # Proceed with authentication
    if camera.login(token, seq_num):
        # Ready to use camera
        pass
else:
    logger.error("Failed to discover camera")
```

## Performance Characteristics

### Expected Connection Times

```
Scenario 1: Direct connection successful on first port
  Time: 0.5 - 1.5 seconds
  Fastest thread wins immediately

Scenario 2: Requires fallback to second/third port
  Time: 2 - 5 seconds
  First timeout (5s) occurs, then successful attempt

Scenario 3: All ports timeout
  Time: 30 seconds (max_connection_time reached)
  All threads exhaust retries
```

### Comparison with Sequential Approach

```
Sequential (Old Approach):
  Port 40611: 5 second timeout
  Port 32100: 5 second timeout
  Port 32108: 1 second success
  Total: 11 seconds

Parallel (New Approach):
  Thread 1 (40611): 5s timeout (running)
  Thread 2 (32100): 5s timeout (running)
  Thread 3 (32108): 1s SUCCESS!
  Total: 1 second (fastest thread wins)

Improvement: 11x faster in this scenario!
```

## Debugging and Logging

### Enable Debug Logging

```python
import logging

# Set up detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger("ConnectionManager")
logger.setLevel(logging.DEBUG)

manager = ParallelConnectionManager(
    camera_ip="192.168.1.100",
    logger=logger
)

success, info = manager.connect_parallel()
```

### Expected Log Output

```
[INFO] [CONNECT] Starting parallel connection attempt...
[DEBUG] [CONNECT] Started thread: p2pConnectThread
[DEBUG] [CONNECT] Started thread: lanConnectThread
[DEBUG] [P2P] Starting P2P direct connection thread
[DEBUG] [LAN] Starting LAN direct connection thread
[DEBUG] [P2P] Attempt 1: local_port=56799, dest_port=40611
[DEBUG] [LAN] Attempt 1: local_port=56800, dest_port=40611
[DEBUG] [P2P] Attempt 2: local_port=56799, dest_port=32100
[DEBUG] [LAN] Attempt 2: local_port=56800, dest_port=32100
[INFO] [P2P] ✓ P2P connection succeeded: port=56799, dest_port=32100, time=2.34s
[DEBUG] [LAN] Another thread succeeded (p2pConnectThread), aborting LAN attempts
[INFO] [CONNECT] Parallel connection attempt completed in 2.35s
```

## Thread Safety

The manager is thread-safe:
- Each thread has its own socket (no sharing)
- Shared state (`_winning_thread_name`) is protected by `threading.Lock`
- Safe to use from main thread or other threads

```python
import threading

def connect_in_background():
    manager = ParallelConnectionManager(camera_ip="192.168.1.100")
    success, info = manager.connect_parallel()
    return success, info

# Run in background thread
thread = threading.Thread(target=connect_in_background, daemon=True)
thread.start()
thread.join(timeout=35)  # Wait up to 35 seconds
```

## Configuration Best Practices

### 1. Destination Ports Order

```python
# Primary (try first)
# |      Secondary
# |      |           Fallback
# |      |           |      
ports = (40611, 32100, 32108, 10000, 80, 57743)
#        Protocol primary ports ^
#                               Universal ports ^
```

### 2. Timeout Settings

```python
# For local networks (LAN only)
max_time = 15.0  # Should connect within 15s if available

# For internet connections (possibly relay)
max_time = 45.0  # Allow more time for relay

# For debugging
max_time = 60.0  # Give plenty of time to observe behavior
```

### 3. Thread Selection

```python
# Always recommended
enable_p2p=True
enable_lan=True

# Only when relay server available
enable_relay=True  # Future: implement first
```

## Future Enhancements

### Relay Server Support

When relay server support is implemented:

```python
manager = ParallelConnectionManager(
    camera_ip="192.168.1.100",
    relay_server="relay.example.com",
    relay_port=12345
)

success, info = manager.connect_parallel(
    enable_relay=True  # Will dynamically negotiate relay port
)
```

### Adaptive Timeout

Future version:

```python
manager = ParallelConnectionManager(
    camera_ip="192.168.1.100",
    adaptive_timeout=True  # Auto-adjust based on conditions
)
```

### Connection Mode Prioritization

Future version:

```python
manager = ParallelConnectionManager(
    camera_ip="192.168.1.100",
    mode_weights={
        'p2p': 1.0,      # Try P2P first (weight 1.0)
        'lan': 0.8,      # Then LAN (weight 0.8)
        'relay': 0.5     # Finally relay (weight 0.5)
    }
)
```

## Comparison with Original Android App

This implementation matches the libArLink.so (PPCS) behavior:

| Feature | libArLink.so | ParallelConnectionManager |
|---------|---|---|
| P2P thread | ✓ | ✓ |
| LAN thread | ✓ | ✓ |
| Relay thread | ✓ | ✗ (future) |
| Parallel execution | ✓ | ✓ |
| First-win pattern | ✓ | ✓ |
| Per-thread sockets | ✓ | ✓ |
| Dynamic relay negotiation | ✓ | ✗ (future) |

## See Also

- **[`docs/PORT_MANAGEMENT_LIBАРLINK_ARCHITECTURE.md`](../docs/PORT_MANAGEMENT_LIBАРLINK_ARCHITECTURE.md)** - Detailed port management and architecture comparison
- **[`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)** - System architecture overview
- **[`docs/PROTOCOL_ANALYSIS.md`](../docs/PROTOCOL_ANALYSIS.md)** - Protocol details
- **`modules/camera_client.py`** - Higher-level connection management
