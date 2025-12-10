# modules/protocol/constants.py
from enum import IntEnum

class PPPPConstants(IntEnum):
    MAGIC_STANDARD = 0xF1

    # Command Types
    CMD_LOGIN = 0xD0      # Login Outer Header
    CMD_DISCOVERY = 0xD1  # Discovery & Heartbeat
    CMD_CONTROL = 0xD3    # Heartbeat (alternative) or Control
    CMD_DATA = 0xD4       # Video/Image Data
    CMD_INIT_BURST = 0xE1 # Initialization (Wake-up)

    # Subcommands (Inner Header)
    SUB_DISCOVERY_RESP = 0x01

    # Defaults
    DEFAULT_SEQUENCE = 1
