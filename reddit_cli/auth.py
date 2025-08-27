from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode
from urllib.request import Request, urlopen


REDDIT_UA = "RedditExplorer/0.1 (by u:example)"


@dataclass
class ScriptCredentials:
    client_id: str
    client_secret: str
    username: str
    password: str


class RedditScriptAuth:
    def __init__(self, creds: ScriptCredentials) -> None:
        self.creds = creds
        self._token: Optional[str] = None
        self._expires_at: float = 0.0

    @staticmethod
    def from_env() -> "RedditScriptAuth":
        cid = os.environ.get("REDDIT_CLIENT_ID", "").strip()
        csec = os.environ.get("REDDIT_CLIENT_SECRET", "").strip()
        user = os.environ.get("REDDIT_USERNAME", "").strip()
        pwd = os.environ.get("REDDIT_PASSWORD", "").strip()
        if not all([cid, csec, user, pwd]):
            raise RuntimeError("Missing Reddit credentials in environment variables")
        return RedditScriptAuth(ScriptCredentials(client_id=cid, client_secret=csec, username=user, password=pwd))

    def _request_token(self) -> None:
        basic = base64.b64encode(f"{self.creds.client_id}:{self.creds.client_secret}".encode()).decode()
        body = urlencode({
            "grant_type": "password",
            "username": self.creds.username,
            "password": self.creds.password,
            "duration": "temporary",
        }).encode()
        req = Request(
            "https://www.reddit.com/api/v1/access_token",
            data=body,
            headers={
                "User-Agent": REDDIT_UA,
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        self._token = data.get("access_token")
        expires_in = int(data.get("expires_in", 3600))
        self._expires_at = time.time() + max(0, expires_in - 30)
        if not self._token:
            raise RuntimeError("Failed to obtain access token")

    def get_token(self) -> str:
        now = time.time()
        if not self._token or now >= self._expires_at:
            self._request_token()
        assert self._token
        return self._token

    def get_current_username(self) -> str:
        token = self.get_token()
        req = Request(
            "https://oauth.reddit.com/api/v1/me",
            headers={
                "User-Agent": REDDIT_UA,
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("name", "")

