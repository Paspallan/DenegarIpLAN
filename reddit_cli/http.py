from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlencode
from urllib.request import Request, urlopen


REDDIT_UA = "RedditExplorer/0.1 (by u:example)"


@dataclass
class HttpClientConfig:
    base_url: str = "https://oauth.reddit.com"
    timeout_seconds: float = 20.0
    min_interval_seconds: float = 0.4


class RedditHttpClient:
    def __init__(self, config: Optional[HttpClientConfig] = None) -> None:
        self.config = config or HttpClientConfig()
        self._last_request_at = 0.0

    def _rate_limit(self) -> None:
        now = time.time()
        elapsed = now - self._last_request_at
        wait = max(0.0, self.config.min_interval_seconds - elapsed)
        if wait > 0:
            time.sleep(wait)
        self._last_request_at = time.time()

    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None, bearer: Optional[str] = None) -> Any:
        self._rate_limit()
        query = f"?{urlencode(params)}" if params else ""
        url = f"{self.config.base_url}{path}{query}"
        headers = {"User-Agent": REDDIT_UA, "Accept": "application/json"}
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        req = Request(url, headers=headers)
        with urlopen(req, timeout=self.config.timeout_seconds) as resp:
            data = resp.read()
            return json.loads(data.decode("utf-8"))

    def __enter__(self) -> "RedditHttpClient":
        return self

    def __exit__(self, *_: Any) -> None:
        return None

