"""High-level device command wrappers.

This module provides convenient methods for sending commands to the camera,
with payload structures matching those observed in the application logs.
"""

import time
import logging
from typing import Optional, Dict, Any, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..camera_client import CameraClient

from .command_ids import (
    CMD_LOGIN,
    CMD_GET_DEV_INFO,
    CMD_START_AV,
    CMD_STOP_AV,
    CMD_GET_MEDIA_LIST,
)


class DeviceCommands:
    """High-level interface for camera device commands.
    
    Provides convenient methods for common camera operations with
    payloads matching the observed protocol structure.
    """

    def __init__(
        self,
        camera_client: "CameraClient",
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize device commands interface.
        
        Args:
            camera_client: CameraClient instance for sending commands
            logger: Optional logger instance
        """
        self.camera_client = camera_client
        self.logger = logger or logging.getLogger(__name__)

    async def login(
        self,
        username: str = "admin",
        password: str = "admin",
        need_video: int = 0,
        need_audio: int = 0,
        support_heartbeat: bool = True,
    ) -> Dict[str, Any]:
        """Login to camera device.
        
        Payload structure from log:
        {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "needAudio": 0,
            "utcTime": 1765218842,
            "supportHeartBeat": true
        }
        
        Args:
            username: Login username (default: "admin")
            password: Login password (default: "admin")
            need_video: Video stream flag (0=no, 1=yes)
            need_audio: Audio stream flag (0=no, 1=yes)
            support_heartbeat: Enable heartbeat mechanism
            
        Returns:
            Login response dict
            
        Raises:
            Exception: If login fails
        """
        payload = {
            "cmdId": CMD_LOGIN,
            "usrName": username,
            "password": password,
            "needVideo": need_video,
            "needAudio": need_audio,
            "utcTime": int(time.time()),
            "supportHeartBeat": support_heartbeat,
        }
        
        self.logger.info(f"[LOGIN] EC_Login, uid:{self.camera_client.device_id}, usrName:{username}")
        
        response = await self.camera_client.send_command(
            cmd_id=CMD_LOGIN,
            payload=payload,
            timeout_sec=10.0,
        )
        
        # Check for successful login
        if response.get("errorCode") == 0:
            self.logger.info(f"[LOGIN] EC_OnLoginResult, errorCode:0, login success")
        else:
            error_code = response.get("errorCode", -1)
            self.logger.error(f"[LOGIN] EC_OnLoginResult, errorCode:{error_code}, login failed")
            raise Exception(f"Login failed with error code: {error_code}")
        
        return response

    async def get_device_info(self, token: Optional[int] = None) -> Dict[str, Any]:
        """Get comprehensive device configuration and status.
        
        Returns device information including:
        - Device ID, firmware versions
        - Model name, product ID
        - Battery status (percentage, charging state)
        - SD card status (total/free space)
        - Settings (work mode, resolutions)
        - Capabilities
        
        Args:
            token: Optional session token
            
        Returns:
            Device info dict with all configuration parameters
            
        Note:
            Response can be large (~3KB) and may be fragmented
        """
        payload = {
            "cmdId": CMD_GET_DEV_INFO,
        }
        
        if token is not None:
            payload["token"] = token
        
        self.logger.debug(f"[DEV_INFO] Requesting device configuration")
        
        response = await self.camera_client.send_command(
            cmd_id=CMD_GET_DEV_INFO,
            payload=payload,
            timeout_sec=10.0,
        )
        
        # Log key device parameters
        if "devId" in response:
            self.logger.info(
                f"[DEV_INFO] Device: {response.get('customName', 'N/A')}, "
                f"Model: {response.get('modelName', 'N/A')}, "
                f"Battery: {response.get('batPercent', 'N/A')}%"
            )
        
        return response

    async def start_av_stream(self, token: int) -> Dict[str, Any]:
        """Start audio/video streaming.
        
        Payload from log: {"cmdId":258,"token":143435880}
        Response: {"errorMsg":"Success","result":0,"cmdId":258}
        
        Args:
            token: Session token
            
        Returns:
            Command response dict
        """
        payload = {
            "cmdId": CMD_START_AV,
            "token": token,
        }
        
        self.logger.info("[AV] Starting audio/video stream")
        
        response = await self.camera_client.send_command(
            cmd_id=CMD_START_AV,
            payload=payload,
            timeout_sec=10.0,
        )
        
        if response.get("result") == 0:
            self.logger.info("[AV] Stream started successfully")
        else:
            self.logger.warning(f"[AV] Start stream result: {response.get('errorMsg')}")
        
        return response

    async def stop_av_stream(self, token: int) -> Dict[str, Any]:
        """Stop audio/video streaming.
        
        Args:
            token: Session token
            
        Returns:
            Command response dict
        """
        payload = {
            "cmdId": CMD_STOP_AV,
            "token": token,
        }
        
        self.logger.info("[AV] Stopping audio/video stream")
        
        response = await self.camera_client.send_command(
            cmd_id=CMD_STOP_AV,
            payload=payload,
            timeout_sec=10.0,
        )
        
        return response

    async def get_media_list(
        self,
        token: int,
        page_no: int = 0,
        items_per_page: int = 45,
    ) -> Dict[str, Any]:
        """Get list of media files (photos/videos) from camera.
        
        Payload structure from log:
        {
            "cmdId": 768,
            "itemCntPerPage": 45,
            "pageNo": 0,
            "token": 143435880
        }
        
        Response structure:
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
        
        Args:
            token: Session token
            page_no: Page number (0-based)
            items_per_page: Number of items per page (default: 45)
            
        Returns:
            Media list response with mediaFiles array
        """
        payload = {
            "cmdId": CMD_GET_MEDIA_LIST,
            "itemCntPerPage": items_per_page,
            "pageNo": page_no,
            "token": token,
        }
        
        self.logger.debug(
            f"[MEDIA] Getting media list: page={page_no}, items={items_per_page}"
        )
        
        response = await self.camera_client.send_command(
            cmd_id=CMD_GET_MEDIA_LIST,
            payload=payload,
            timeout_sec=15.0,  # Longer timeout for potentially large response
        )
        
        if "mediaFiles" in response:
            count = len(response["mediaFiles"])
            total = response.get("cnt", count)
            self.logger.info(
                f"[MEDIA] Retrieved {count} media files (page {page_no}, total: {total})"
            )
        
        return response

    async def get_all_media_files(
        self,
        token: int,
        items_per_page: int = 45,
    ) -> List[Dict[str, Any]]:
        """Get all media files by paginating through all pages.
        
        Args:
            token: Session token
            items_per_page: Number of items per page
            
        Returns:
            List of all media file dicts
        """
        all_media = []
        page_no = 0
        
        while True:
            response = await self.get_media_list(
                token=token,
                page_no=page_no,
                items_per_page=items_per_page,
            )
            
            media_files = response.get("mediaFiles", [])
            if not media_files:
                break
            
            all_media.extend(media_files)
            
            # Check if there are more pages
            if len(media_files) < items_per_page:
                break
            
            page_no += 1
        
        self.logger.info(f"[MEDIA] Retrieved total of {len(all_media)} media files")
        return all_media
