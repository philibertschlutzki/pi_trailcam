#!/usr/bin/env python3
"""
TrailCam Go Log Generator

Reverses the log format from the Android TrailCam Go app to generate similar logs.
Supports both Android Debug Logs and Native SDK Logs.
"""

import json
import random
import time
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from enum import Enum
import hashlib
import secrets


class LogLevel(Enum):
    """Log levels from Android and TrailCam SDK"""
    DEBUG = 'D'
    INFO = 'INFO'
    WARNING = 'WARN'
    ERROR = 'E'


@dataclass
class StackTraceFrame:
    """Represents a stack trace frame in the log"""
    class_name: str
    method_name: str
    file_name: str
    line_number: int

    def format_android(self) -> str:
        """Format as Android log stack trace"""
        return f"\t├ {self.class_name}.{self.method_name}({self.file_name}:{self.line_number})"


@dataclass
class AndroidLogEntry:
    """Android-style debug log entry"""
    timestamp: datetime
    log_level: LogLevel
    tag: str
    thread: str
    message: str
    stack_frames: List[StackTraceFrame]

    def format(self) -> str:
        """Format log entry in Android style"""
        # Main log line
        ms = self.timestamp.microsecond // 1000
        time_str = self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        main_line = f"{time_str}.{ms:03d} {self.log_level.value}/{self.tag}: Thread: {self.thread}"
        
        # Stack trace
        lines = [main_line]
        for i, frame in enumerate(self.stack_frames):
            if i == len(self.stack_frames) - 1:
                lines.append(frame.format_android().replace('├', '└'))
            else:
                lines.append(frame.format_android())
        
        # Message
        lines.append(self.message)
        return '\n'.join(lines)


@dataclass
class NativeLogEntry:
    """Native SDK log entry (from C++ Artemis SDK)"""
    timestamp: datetime
    log_level: LogLevel
    tag: str
    message: str

    def format(self) -> str:
        """Format log entry in native style"""
        time_str = self.timestamp.strftime('[%Y-%m-%d %H:%M:%S.%f]')[:-4]  # Remove last 3 digits of microseconds
        level_str = f"[{self.log_level.value}]"
        tag_str = f"[{self.tag}]" if self.tag else ""
        return f"{time_str}{level_str}{tag_str} {self.message}"


class TrailCamLogGenerator:
    """Generate TrailCam Go-style logs"""

    # Common Android classes from the app
    ANDROID_CLASSES = [
        ('com.example.baseuitls.LogUtil', 'd', 'LogUtil.java'),
        ('com.example.baseuitls.LogUtil', 'e', 'LogUtil.java'),
        ('com.xlink.trailcamgo.TheApp', 'onCreate', 'TheApp.java'),
        ('com.xlink.trailcamgo.TheApp', 'connectToNetwork', 'TheApp.java'),
        ('com.xlink.trailcamgo.activity.MainActivity', 'onCreate', 'MainActivity.java'),
        ('com.xlink.trailcamgo.activity.SplashActivity', 'onCreate', 'SplashActivity.java'),
        ('com.xlink.trailcamgo.activity.HomeFragment', 'onCreateView', 'HomeFragment.java'),
        ('com.xlink.trailcamgo.activity.dev_view.DevViewCameraFragment', 'onVisibleStatusChanged', 'DevViewCameraFragment.java'),
        ('com.xlink.trailcamgo.cloud.request.VolleyUtil$Builder', 'getJsonObjReq', 'VolleyUtil.java'),
        ('com.xlink.trailcamgo.utils.NetUtils', 'checkVPN', 'NetUtils.java'),
        ('com.xlink.trailcamgo.utils.BluetoothUtils', 'startConnectToDev', 'BluetoothUtils.java'),
        ('com.xlink.trailcamgo.widgets.DevSetupDialog', 'handleMsg', 'DevSetupDialog.java'),
    ]

    # Android threads
    ANDROID_THREADS = [
        'main',
        'Binder:22601_4',
        'BleDataSend',
        'ConnectivityThread',
    ]

    # Device information
    DEVICE_INFO = {
        'manufacturer': 'HUAWEI',
        'model': 'LYA-L29',
        'android_version': '10',
        'sdk_level': '29',
    }

    # API endpoints
    API_ENDPOINTS = [
        'https://push-fep.myfoscam.com/jpush_logout',
        'https://push-fep.myfoscam.com/fcm_login',
        'https://api.myfoscam.com/user/report_info/',
        'https://api.myfoscam.com/gateway',
        'https://api.myfoscam.com/user_ipc_setting_v3_0/get_all_devices',
    ]

    def __init__(self, start_time: Optional[datetime] = None):
        """Initialize the log generator"""
        self.start_time = start_time or datetime(2025, 12, 8, 18, 33, 41, 620000)
        self.current_time = self.start_time
        self.logs: List[str] = []
        self.device_id = self._generate_device_id()
        self.user_tag = self._generate_user_tag()
        self.open_id = self._generate_open_id()
        self.access_token = self._generate_access_token()

    def _generate_device_id(self) -> str:
        """Generate a random device ID"""
        return ':'.join([f"{random.randint(0, 255):02X}" for _ in range(6)])

    def _generate_user_tag(self) -> str:
        """Generate a random user tag"""
        return secrets.token_hex(8)

    def _generate_open_id(self) -> str:
        """Generate a random open ID"""
        return secrets.token_hex(13)

    def _generate_access_token(self) -> str:
        """Generate a random access token"""
        return secrets.token_hex(16)

    def _advance_time(self, milliseconds: int = 0):
        """Advance internal timestamp"""
        self.current_time += timedelta(milliseconds=milliseconds)

    def add_android_log(
        self,
        message: str,
        log_level: LogLevel = LogLevel.DEBUG,
        tag: str = "trailCam go",
        thread: str = "main",
        stack_frames: Optional[List[tuple]] = None,
        advance_ms: int = 0
    ) -> 'TrailCamLogGenerator':
        """Add an Android-style log entry"""
        if advance_ms:
            self._advance_time(advance_ms)

        frames = []
        if stack_frames:
            frames = [StackTraceFrame(*frame) for frame in stack_frames]

        log_entry = AndroidLogEntry(
            timestamp=self.current_time,
            log_level=log_level,
            tag=tag,
            thread=thread,
            message=message,
            stack_frames=frames
        )
        self.logs.append(log_entry.format())
        return self

    def add_native_log(
        self,
        message: str,
        log_level: LogLevel = LogLevel.INFO,
        tag: str = "EC_JNI",
        advance_ms: int = 0
    ) -> 'TrailCamLogGenerator':
        """Add a native SDK log entry"""
        if advance_ms:
            self._advance_time(advance_ms)

        log_entry = NativeLogEntry(
            timestamp=self.current_time,
            log_level=log_level,
            tag=tag,
            message=message
        )
        self.logs.append(log_entry.format())
        return self

    def add_http_request(
        self,
        endpoint: str,
        method: str = "POST",
        params: Optional[Dict[str, Any]] = None
    ) -> 'TrailCamLogGenerator':
        """Add an HTTP request log"""
        param_str = ""
        if params:
            param_str = f"   参数: {json.dumps(params)}"
        
        message = f"http请求: {endpoint}{param_str}"
        return self.add_android_log(
            message=message,
            log_level=LogLevel.ERROR,
            stack_frames=[
                ('com.example.baseuitls.LogUtil', 'e', 'LogUtil.java', 84),
                ('com.xlink.trailcamgo.cloud.request.VolleyUtil$Builder', 'getJsonObjReq', 'VolleyUtil.java', 221)
            ],
            advance_ms=50
        )

    def add_ble_connection_sequence(self) -> 'TrailCamLogGenerator':
        """Add a Bluetooth LE connection sequence"""
        # Check VPN
        self.add_android_log(
            "check current network isVPN false",
            thread="main",
            stack_frames=[
                ('com.example.baseuitls.LogUtil', 'd', 'LogUtil.java', 97),
                ('com.xlink.trailcamgo.utils.NetUtils', 'checkVPN', 'NetUtils.java', 47)
            ],
            advance_ms=3000
        )
        
        # Start BLE connection
        self.add_android_log(
            "wu tag setup create handle -1",
            thread="main",
            stack_frames=[
                ('com.example.baseuitls.LogUtil', 'd', 'LogUtil.java', 72),
                ('com.xlink.trailcamgo.widgets.DevSetupDialog', 'startConnectToDev', 'DevSetupDialog.java', 1148)
            ],
            advance_ms=0
        )
        
        self.add_android_log(
            "current connect wifi device product 115 modelName is KJK",
            thread="main",
            stack_frames=[
                ('com.example.baseuitls.LogUtil', 'd', 'LogUtil.java', 97),
                ('com.xlink.trailcamgo.widgets.DevSetupDialog', 'startConnectToDev', 'DevSetupDialog.java', 1172)
            ],
            advance_ms=5
        )
        
        self.add_android_log(
            "Start connect bluetooth",
            thread="main",
            stack_frames=[
                ('com.example.baseuitls.LogUtil', 'd', 'LogUtil.java', 72),
                ('com.xlink.trailcamgo.utils.BluetoothUtils', 'startConnectToDev', 'BluetoothUtils.java', 477)
            ],
            advance_ms=1
        )
        
        self.add_android_log(
            "bluetoothDevice connectGatt  autoConnect 0",
            thread="main",
            stack_frames=[
                ('com.example.baseuitls.LogUtil', 'd', 'LogUtil.java', 97),
                ('com.xlink.trailcamgo.utils.BluetoothUtils', 'startConnectToDev', 'BluetoothUtils.java', 485)
            ],
            advance_ms=3
        )
        
        # BLE connection established
        self.add_android_log(
            "BluetoothGattCallback connected",
            thread="Binder:22601_4",
            stack_frames=[
                ('com.example.baseuitls.LogUtil', 'd', 'LogUtil.java', 72),
                ('com.xlink.trailcamgo.utils.BluetoothUtils$2', 'onConnectionStateChange', 'BluetoothUtils.java', 217)
            ],
            advance_ms=3562
        )
        
        return self

    def add_device_login_sequence(self) -> 'TrailCamLogGenerator':
        """Add device login sequence with native SDK logs"""
        self.add_native_log(
            "logIn",
            log_level=LogLevel.INFO,
            tag="EC_JNI",
            advance_ms=2650
        )
        
        self.add_native_log(
            f"EC_Login, uid:LBCS-000000-CCCJJ, usrName:admin, password:admin, handle:0",
            log_level=LogLevel.INFO,
            advance_ms=0
        )
        
        self.add_native_log(
            "Enter cmdSendThread, fd:-1",
            log_level=LogLevel.INFO,
            advance_ms=0
        )
        
        self.add_native_log(
            "Enter audioSendThread",
            log_level=LogLevel.INFO,
            advance_ms=0
        )
        
        self.add_native_log(
            "Start lan connect to:LBCS-000000-CCCJJ, connectType:1, bEnableLanSearch:      3f",
            log_level=LogLevel.INFO,
            advance_ms=5
        )
        
        self.add_native_log(
            "Start connect by lan, port:35281",
            log_level=LogLevel.INFO,
            advance_ms=1
        )
        
        self.add_native_log(
            "Lan connect to remote success, mode:P2P, cost time:0, localAddr:(192.168.43.1:35281), remoteAddr:(192.168.43.1:40611)",
            log_level=LogLevel.INFO,
            advance_ms=359
        )
        
        self.add_native_log(
            "Lan connect to remote success, start wait ACK, mNeedBreakConnect:0",
            log_level=LogLevel.INFO,
            advance_ms=0
        )
        
        self.add_native_log(
            "LAN connect wait ACK success",
            log_level=LogLevel.INFO,
            advance_ms=4
        )
        
        return self

    def add_heartbeat_sequence(self, count: int = 1) -> 'TrailCamLogGenerator':
        """Add heartbeat/ping command sequence"""
        for i in range(count):
            self.add_native_log(
                '{"cmdId":525}',
                log_level=LogLevel.WARNING,
                advance_ms=3000 if i > 0 else 0
            )
            
            self.add_native_log(
                "Add cmd to cmd queue success",
                log_level=LogLevel.INFO,
                advance_ms=0
            )
            
            self.add_native_log(
                '{"cmdId":525}',
                log_level=LogLevel.WARNING,
                advance_ms=0
            )
            
            self.add_native_log(
                "Start send cmd to dev, len:45",
                log_level=LogLevel.INFO,
                advance_ms=2
            )
            
            self.add_native_log(
                "Send cmd, len:45",
                log_level=LogLevel.INFO,
                advance_ms=0
            )
            
            self.add_native_log(
                "Send cmd to dev complete, len:45",
                log_level=LogLevel.INFO,
                advance_ms=0
            )
        
        return self

    def generate(self) -> str:
        """Generate the complete log file"""
        return '\n'.join(self.logs)

    def save(self, filename: str):
        """Save the generated log to a file"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(self.generate())
        print(f"Log saved to {filename}")


def main():
    """Main function demonstrating the log generator"""
    # Create generator
    generator = TrailCamLogGenerator()
    
    # Simulate app startup
    generator.add_android_log(
        "Thread: main",
        thread="main",
        stack_frames=[
            ('com.example.baseuitls.LogUtil', 'd', 'LogUtil.java', 97),
            ('com.xlink.trailcamgo.TheApp', 'onCreate', 'TheApp.java', 382)
        ]
    )
    
    generator.add_android_log(
        "开始启动 initData",
        thread="main",
        stack_frames=[
            ('com.example.baseuitls.LogUtil', 'd', 'LogUtil.java', 97),
            ('com.xlink.trailcamgo.TheApp', 'onCreate', 'TheApp.java', 384)
        ],
        advance_ms=0
    )
    
    # Device info
    device_info = f"HUAWEI,LYA-L29,Android:10, SDK:29,手机型号:HUAWEILYA-L2910 App:2.5.2"
    generator.add_android_log(
        device_info,
        thread="main",
        advance_ms=56
    )
    
    # API requests
    generator.add_http_request(
        'https://push-fep.myfoscam.com/jpush_logout',
        params={'userTag': generator.user_tag, 'appToken': 'example_token'}
    )
    
    generator.add_http_request(
        'https://api.myfoscam.com/user/report_info/',
        params={
            'country': 'CH',
            'appVersion': '2.5.2',
            'clientId': 'oem-6790',
            'openId': generator.open_id,
            'accessToken': generator.access_token
        }
    )
    
    # BLE connection
    generator.add_ble_connection_sequence()
    
    # Device login
    generator.add_device_login_sequence()
    
    # Heartbeat sequence
    generator.add_heartbeat_sequence(count=5)
    
    # Save to file
    generator.save('generated_log.txt')
    
    # Also print a sample
    print("\n" + "="*80)
    print("Sample generated log output:")
    print("="*80 + "\n")
    print(generator.generate()[:2000] + "\n...\n")


if __name__ == '__main__':
    main()
