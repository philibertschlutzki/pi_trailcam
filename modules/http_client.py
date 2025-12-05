import requests
import os
import logging
import config
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class HttpClient:
    """
    Handles HTTP interactions with the Camera's Web Server.
    """

    def __init__(self):
        self.base_url = config.CAM_BASE_URL
        self.download_dir = config.DOWNLOAD_DIR

        # Create download directory if it doesn't exist
        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir)

    def is_reachable(self):
        """Checks if the camera HTTP server is reachable."""
        try:
            response = requests.get(self.base_url, timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def list_files(self):
        """
        Retrieves the list of files from the camera.

        Since we don't have the exact API, this is a placeholder/heuristic implementation.
        Real implementation would involve:
        1. Fetching the index page (HTML) or an API endpoint (JSON/XML).
        2. Parsing the response to extract file URLs.

        Returns:
            list: A list of full URLs to media files.
        """
        logger.info(f"Fetching file list from {self.base_url}...")

        # [PLACEHOLDER LOGIC]
        # In a real scenario, you would inspect the HTML or JSON response.
        # Example heuristic for a directory listing:
        try:
            response = requests.get(self.base_url, timeout=10)
            response.raise_for_status()

            # Simple mock parsing: Find all links ending in .JPG or .MP4
            # This relies on the camera serving a simple Apache/Lighttpd directory listing.
            files = []

            # Crude parsing for demonstration. Use BeautifulSoup in production if needed.
            # Assuming format: <a href="DCIM/100MEDIA/IMG_001.JPG">...
            from html.parser import HTMLParser

            class SimpleLinkParser(HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.links = []
                def handle_starttag(self, tag, attrs):
                    if tag == 'a':
                        for attr in attrs:
                            if attr[0] == 'href':
                                href = attr[1]
                                if href.upper().endswith(('.JPG', '.MP4', '.AVI', '.MOV')):
                                    self.links.append(href)

            parser = SimpleLinkParser()
            parser.feed(response.text)

            # Construct full URLs
            for link in parser.links:
                full_url = urljoin(self.base_url, link)
                files.append(full_url)

            logger.info(f"Found {len(files)} potential media files.")
            return files

        except Exception as e:
            logger.error(f"Failed to list files: {e}")
            return []

    def download_file(self, url):
        """
        Downloads a file from the given URL to the local download directory.
        Skips if file already exists with same size.
        """
        filename = url.split('/')[-1]
        local_path = os.path.join(self.download_dir, filename)

        logger.info(f"Processing {filename}...")

        try:
            # Check if file exists
            if os.path.exists(local_path):
                # Optional: Check remote file size to resume or skip
                # head = requests.head(url, timeout=5)
                # remote_size = int(head.headers.get('content-length', 0))
                # if os.path.getsize(local_path) == remote_size:
                logger.info(f"File {filename} already exists. Skipping.")
                return True

            # Download with stream
            with requests.get(url, stream=True, timeout=30) as r:
                r.raise_for_status()
                with open(local_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)

            logger.info(f"Downloaded {filename} successfully.")
            return True

        except Exception as e:
            logger.error(f"Failed to download {url}: {e}")
            return False
