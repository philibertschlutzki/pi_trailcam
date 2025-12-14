# modules/protocol/constants.py
from enum import IntEnum

class PPPPConstants(IntEnum):
    MAGIC_STANDARD = 0xF1

    # Command Types
    CMD_INIT_PING = 0xE0     # First initialization packet (Wake-up Phase 1)
    CMD_INIT_SECONDARY = 0xE1 # Second initialization packet (Wake-up Phase 2)
    CMD_LAN_SEARCH = 0x30    # LAN Search Broadcast (Phase 1 Discovery)
    CMD_LOGIN = 0xD0         # Login Outer Header
    CMD_DISCOVERY = 0xD1     # Discovery & Heartbeat
    CMD_CONTROL = 0xD3       # Heartbeat (alternative) or Control
    CMD_DATA = 0xD4          # Video/Image Data
    
    # Legacy alias for backward compatibility
    CMD_INIT_BURST = 0xE1    # Deprecated: Use CMD_INIT_SECONDARY

    # Subcommands (Inner Header)
    SUB_DISCOVERY_RESP = 0x01

    # Defaults
    DEFAULT_SEQUENCE = 1
