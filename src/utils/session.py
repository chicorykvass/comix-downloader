"""
Session management with FlareSolverr fallback.
"""

import requests
import time
import threading
from typing import Any
from .logger import get_logger

logger = get_logger(__name__)

class SessionManager:
    """Manages requests session with FlareSolverr fallback for Cloudflare."""
    
    def __init__(self):
        self.session = requests.Session()
        self._lock = threading.Lock()
        # Set default headers - using a more realistic, modern User-Agent
        self.session.headers.update({
            "Referer": "https://comix.to/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
        })
        from .config import ConfigManager
        self._config = ConfigManager()
        self.flaresolverr_url = self._config.get("flaresolverr_url", "http://localhost:8191/v1")
        self._flaresolverr_triggered = False

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        """Execute a GET request, falling back to FlareSolverr if blocked."""
        force_flare = kwargs.pop("force_flare", False)
        
        if force_flare:
            with self._lock:
                logger.info(f"Forcing FlareSolverr bypass for {url}...")
                if self._solve_cloudflare(url):
                    return self.session.get(url, **kwargs)
                else:
                    logger.error("Forced FlareSolverr bypass failed. Attempting normal request...")

        try:
            response = self.session.get(url, **kwargs)
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise

        # Detection logic for Cloudflare / blocking
        is_cloudflare = "cloudflare" in response.headers.get("Server", "").lower()
        is_error_status = response.status_code in [403, 503, 429]
        # Only check for textual challenges if the response is actually a text format
        # Parsing large binary images as text is extremely slow and causes hangs
        content_type = response.headers.get("Content-Type", "").lower()
        is_text = "text/html" in content_type or "application/json" in content_type
        
        has_challenge = False
        if is_text and any(text in response.text for text in ["Checking your browser", "Just a moment", "cf-browser-verification", "Ray ID:"]):
            has_challenge = True
        
        # Also check for empty/null results if it looks like an API-level block (specific to Comix)
        is_empty_result = False
        try:
            if response.status_code == 200 and "application/json" in content_type:
                json_data = response.json()
                if json_data.get("result") is None and json_data.get("status") == "error":
                    is_empty_result = True
                    logger.warning(f"API returned error status for {url}. Might need bypass.")
        except Exception:
            pass

        if is_error_status or has_challenge or is_empty_result:
            if is_cloudflare or has_challenge or is_empty_result:
                with self._lock:
                    # Check again inside lock to see if another thread already solved it
                    logger.warning(f"Block or challenge detected for {url} (Status: {response.status_code}). Attempting FlareSolverr bypass...")
                    if self._solve_cloudflare(url):
                        # Retry request
                        logger.debug(f"Retrying request to {url} after FlareSolverr bypass.")
                        response = self.session.get(url, **kwargs)
                    else:
                        logger.error("FlareSolverr bypass failed or FlareSolverr not running.")
            elif response.status_code == 429:
                logger.warning(f"Rate limited (429) for {url}. Waiting 5 seconds...")
                time.sleep(5)
                response = self.session.get(url, **kwargs)
                
        return response

    def _solve_cloudflare(self, target_url: str) -> bool:
        """Use FlareSolverr to get clearance cookies."""
        try:
            # Create session - using shorter timeout for connection to avoid long hangs
            logger.debug(f"Creating FlareSolverr session at {self.flaresolverr_url}...")
            session_res = requests.post(self.flaresolverr_url, json={
                "cmd": "sessions.create"
            }, timeout=10).json()
            
            if session_res.get("status") != "ok":
                logger.error(f"Failed to create FlareSolverr session: {session_res}")
                return False
                
            session_id = session_res.get("session")
            
            # Request URL via FlareSolverr
            logger.debug(f"Requesting {target_url} via FlareSolverr...")
            req_res = requests.post(self.flaresolverr_url, json={
                "cmd": "request.get",
                "url": target_url,
                "session": session_id,
                "maxTimeout": 60000
            }, timeout=65).json()
            
            if req_res.get("status") == "ok":
                solution = req_res.get("solution", {})
                
                # Update cookies
                cookies = solution.get("cookies", [])
                for cookie in cookies:
                    self.session.cookies.set(cookie["name"], cookie["value"], domain=cookie.get("domain", ""))
                    
                # Update user agent
                user_agent = solution.get("userAgent")
                if user_agent:
                    self.session.headers.update({"User-Agent": user_agent})
                    
                logger.info(f"Successfully bypassed Cloudflare. Got {len(cookies)} cookies.")
                success = True
            else:
                logger.error(f"FlareSolverr request failed: {req_res}")
                success = False
                
            # Destroy session
            requests.post(self.flaresolverr_url, json={
                "cmd": "sessions.destroy",
                "session": session_id
            }, timeout=10)
            
            return success
            
        except Exception as e:
            logger.error(f"Error during FlareSolverr bypass: {e}")
            return False

# Singleton instance
_session_manager = None

def get_session() -> SessionManager:
    """Get the singleton session manager."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
