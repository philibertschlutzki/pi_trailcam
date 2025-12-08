# Port Management & libArLink.so Architecture

## Overview

This document explains how the original Android TrailCam Go app (libArLink.so) manages ports and establishes connections, and how we've implemented a Python equivalent inspired by its architecture.

## The Problem: Sequential vs. Parallel Connection

### Original Approach (libArLink.so)

The PPCS (P2P Push Proxy Connection Service) library uses a **multi-threaded parallel connection strategy**:

```c
// Three threads start simultaneously
thread_1: p2pConnectThread()     // UDP P2P direct
thread_2: lanConnectThread()     // UDP LAN direct  
thread_3: relayConnectThread()   // TCP Relay via server

// First to succeed wins, others are terminated
// Average connection time: 1-3 seconds
```

### Python Client Approach (Before Enhancement)

The initial Python implementation used **sequential single-threaded approach**:

```python
for dest_port in [40611, 32100, 32108, ...]:
    socket = create_socket(port=0)  # OS assigns port
    try_connect(socket, dest_port)
    if timeout:
        socket.close()
        retry_next_port()
```

**Problem**: On failed attempts, the code would cache `source_port = None`, leading to:
```
TypeError: 'NoneType' object cannot be interpreted as an integer
```

## The libArLink.so Socket Architecture

### Key Principle: Per-Thread Socket Management

```c
// CORRECT (libArLink.so):
void* p2pConnectThread(void* arg) {
    int socket_fd;      // LOCAL variable, not global!
    int local_port;
    
    for (int dest_port in DEST_PORTS) {
        socket_fd = socket(AF_INET, SOCK_DGRAM);
        bind(socket_fd, ..., port=0);  // OS assigns
        
        if (try_discovery(socket_fd, dest_port)) {
            return (void*)socket_fd;    // SUCCESS
        }
        
        close(socket_fd);   // Port reclaimed by OS
        // Next loop: new socket, new port
    }
    return NULL;  // FAILURE
}
```

### Critical Differences

| Aspect | libArLink.so | Initial Python Client |
|--------|---|---|
| **Port Caching** | None (per-thread local) | Global `cached_source_port` |
| **Socket Creation** | One per attempt | One and reused |
| **Parallelism** | 3 threads racing | Sequential retries |
| **Retry Strategy** | Automatic per thread | Manual loop-based |
| **Error on `None`** | Impossible | Happens in Issue #32 |
| **Port Reclamation** | Automatic on close | Manual |

## Issue #32: The NoneType Bug

### Symptom
```
2025-12-08 20:25:43,312 - Main - ERROR - [SOCKET] Creation failed: 'NoneType' object cannot be interpreted as an integer
2025-12-08 20:25:43,312 - Main - ERROR - [DISCOVERY] Failed to bind source port None
```

### Root Cause

```python
# Global variable initialized with None
cached_source_port = None

# Loop using it
for attempt in range(5):
    if attempt == 0:
        source_port = 0  # First time: request OS-assigned
    else:
        source_port = cached_source_port  # Second time: None!
    
    socket.bind(('', source_port))  # ✗ TypeError: NoneType
```

### Why libArLink.so Doesn't Have This Bug

```c
// Each thread has its OWN socket variable
void* thread_1(void* arg) {
    int socket_fd;  // Local, per-thread
    // ...
}

void* thread_2(void* arg) {
    int socket_fd;  // Different local variable
    // ...
}

// No global "cached port" that can be None!
```

## The Fix: FIX #32 Implementation

### Guard Clause Approach

```python
for attempt in range(max_retries):
    if attempt == 0:
        source_port = 0
    else:
        # FIX #32: Check for None before using
        if cached_source_port:
            source_port = cached_source_port
        else:
            source_port = 0  # Fallback
    
    socket.bind(('', source_port))
```

### Port Reclamation on Discovery Failure

```python
if discover_device(source_port):
    cached_source_port = self.active_port  # SUCCESS: Cache it
else:
    # FIX #32: Even on failure, keep the port if binding succeeded
    if self.active_port:
        cached_source_port = self.active_port  # Cache for retry
    
    socket.close()  # OS reclaims port
```

## The Enhancement: Parallel Connection Manager

### New Architecture

The `connection_manager.py` module implements the full libArLink.so parallel strategy:

```python
from modules.connection_manager import ParallelConnectionManager

manager = ParallelConnectionManager(
    camera_ip="192.168.1.100",
    destination_ports=(40611, 32100, 32108, 10000, 80, 57743),
    max_connection_time=30.0
)

success, info = manager.connect_parallel(
    enable_p2p=True,
    enable_lan=True,
    enable_relay=False  # Not yet implemented
)

if success:
    print(f"Connected via {info['winning_thread']}: port {info['port']}")
```

### Thread States (from libArLink.so)

Each thread tracks:

```python
@dataclass
class ThreadSocketInfo:
    thread_name: str  # "p2pConnectThread", "lanConnectThread", etc
    mode: ConnectionMode  # P2P, LAN, or RELAY
    socket_fd: Optional[socket.socket]  # Per-thread socket
    local_port: Optional[int]  # OS-assigned ephemeral port
    destination_port: Optional[int]  # Which port it's trying
    retry_count: int  # Attempts made
    state: ConnectionThreadState  # PENDING, RUNNING, SUCCESS, FAILED
    error: Optional[str]  # Error message if failed
```

### Key Design Decisions

#### 1. **Local Socket Variables**
```python
def _p2p_connect_thread(self):
    # Each thread creates its OWN socket, not shared
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))  # OS assigns port
    local_port = sock.getsockname()[1]
    # No global caching within thread!
```

#### 2. **Automatic Port Reclamation**
```python
if connection_failed:
    sock.close()  # OS automatically reclaims ephemeral port
    # Next iteration gets a different port via OS
```

#### 3. **First-Win Architecture**
```python
# Check if another thread already succeeded
if self._winning_thread_name is not None:
    # Another thread won - cancel this one
    return

# If we succeed
self._winning_thread_name = "p2pConnectThread"
# Other threads will see this and exit
```

#### 4. **No Global Port Caching Between Threads**
```python
# Each thread manages its own port lifecycle
# No shared "cached_source_port" that can become None
# Different threads use different ports simultaneously
```

## Comparison: Issue #32 Bug Prevention

### Sequential Approach (Initial Python)
```python
cached_source_port = None  # ← Global, can be None

for attempt in range(5):
    source_port = cached_source_port  # ← Bug: None on 2nd attempt
```

### Parallel Approach (New Manager)
```python
class _p2pConnectThread:
    def _p2p_connect_thread(self):
        for dest_port in self.destination_ports:
            sock = socket.socket(...)  # ← New socket each time
            sock.bind(("", 0))  # ← Always works, port is local
            local_port = sock.getsockname()[1]  # ← Never None
            
            if try_connection(sock):
                # Store port only on SUCCESS
                return True
            
            sock.close()  # ← Cleanup
```

**Key difference**: Port is obtained from socket, not from cached variable.

## Performance Impact

### Sequential (Before)
```
Attempt 1: port=40611 → Timeout (5s)
Attempt 2: port=32100 → Timeout (5s)
Attempt 3: port=32108 → Timeout (5s)
Total: 15 seconds
```

### Parallel (After)
```
Thread 1: port=40611 → Timeout (5s)
Thread 2: port=32100 → Timeout (5s)
Thread 3: port=32108 → SUCCESS (1s)
Total: 5 seconds (fastest thread wins)
```

**Expected improvement: 2-3x faster connection establishment**

## PPCS Protocol Details

The original PPCS library includes dynamic port negotiation:

```c
// From libArLink.so symbols:
cs2p2pPPPPProtoSendRlyPort(...)      // Request relay port
cs2p2pPPPPProtoReadRlyPortAck(...)   // Receive assigned port
```

This is more sophisticated than the Python hardcoded port list approach:
- **libArLink.so**: Dynamically negotiates with relay server
- **Python**: Uses static port list `[40611, 32100, 32108, ...]`

The parallel manager is designed to support dynamic relay negotiation in future versions.

## Configuration Recommendations

```python
# In config.py:

# Destination ports to try (in order)
DESTINATION_PORTS = (40611, 32100, 32108, 10000, 80, 57743)

# Maximum time to spend attempting connections
MAX_CONNECTION_TIME = 30.0  # seconds

# Enable/disable connection modes
ENABLE_P2P_CONNECTION = True
ENABLE_LAN_CONNECTION = True
ENABLE_RELAY_CONNECTION = False  # Not implemented

# Camera startup delay (reduced from 8s to 1s after FIX #31)
CAMERA_STARTUP_DELAY = 1  # seconds
```

## Thread Safety

The implementation uses locks for shared state:

```python
self._lock = threading.Lock()

# When a thread succeeds
with self._lock:
    self._winning_thread_name = "p2pConnectThread"

# Other threads check without lock (read-only)
if self._winning_thread_name is not None:
    return  # Exit
```

## Migration Path

### Phase 1: Guard Clause (Done - FIX #32)
Add `if cached_source_port:` guard to prevent None errors.

### Phase 2: Per-Thread Sockets (Current)
Introduce `ParallelConnectionManager` for better architecture.

### Phase 3: Full Integration
Replace sequential connection logic with parallel manager in `camera_client.py`.

### Phase 4: Dynamic Relay Support
Implement dynamic relay port negotiation matching original PPCS.

## References

- **libArLink.so**: Original PPCS library in Android APK
  - Path: `tests/APK/config.armeabi_v7a/lib/armeabi-v7a/libArLink.so`
  - Symbols: extracted to `docs/findings.txt`

- **Issue #32**: "False PORT" - NoneType crash on reconnection
  - Problem: Global `cached_source_port` initialized as None
  - Solution: Guard clause + parallel threads

- **FIX #31 & #32**: Connection retry crash
  - PR #33: Implemented guard clause and timing optimization

- **PROTOCOL_ANALYSIS.md**: Detailed ARTEMIS protocol documentation

## Future Enhancements

1. **Relay Server Support**
   - Implement `_relay_connect_thread()` with proper negotiation
   - Handle dynamic relay port assignment

2. **Adaptive Timeouts**
   - Per-thread timeout based on network conditions
   - Exponential backoff for repeated failures

3. **Connection Pooling**
   - Reuse successful sockets
   - Maintain multiple connections for parallel operations

4. **Statistics/Telemetry**
   - Track which thread typically succeeds first
   - Record failure patterns for debugging
   - Estimate optimal timeout values

5. **Connection Mode Prioritization**
   - Weight threads based on historical success
   - Skip unreliable modes after repeated failures
