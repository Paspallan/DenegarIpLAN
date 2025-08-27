from __future__ import annotations

import json
import mimetypes
import os
import time
from typing import Any, Dict, Tuple
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .auth import RedditScriptAuth
from .http import REDDIT_UA


def _post_json(url: str, payload: Dict[str, Any], bearer: str, timeout: int = 30, retries: int = 3) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    last_err = None
    for attempt in range(retries):
        req = Request(
            url,
            data=data,
            headers={
                "User-Agent": REDDIT_UA,
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            last_err = e
            time.sleep(1 + attempt)
    raise last_err  # type: ignore[misc]


def _multipart_post(url: str, fields: Dict[str, str], file_field_name: str, file_tuple: Tuple[str, bytes, str], timeout: int = 60) -> bytes:
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    lines = []
    for k, v in fields.items():
        lines.append(f"--{boundary}\r\n")
        lines.append(f"Content-Disposition: form-data; name=\"{k}\"\r\n\r\n")
        lines.append(f"{v}\r\n")
    filename, file_bytes, content_type = file_tuple
    lines.append(f"--{boundary}\r\n")
    lines.append(
        f"Content-Disposition: form-data; name=\"{file_field_name}\"; filename=\"{filename}\"\r\n"
    )
    lines.append(f"Content-Type: {content_type}\r\n\r\n")
    body_start = ("".join(lines)).encode("utf-8")
    body_end = f"\r\n--{boundary}--\r\n".encode("utf-8")
    body = body_start + file_bytes + body_end
    req = Request(
        url,
        data=body,
        headers={
            "User-Agent": REDDIT_UA,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Accept": "*/*",
        },
        method="POST",
    )
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def upload_image_and_get_media_id(auth: RedditScriptAuth, image_path: str) -> str:
    bearer = auth.get_token()
    guessed = mimetypes.guess_type(image_path)[0] or "image/jpeg"
    asset_req = {
        "filepath": os.path.basename(image_path),
        "mimetype": guessed,
        "upload_type": "img",
    }
    init = _post_json("https://oauth.reddit.com/api/media/asset.json", asset_req, bearer, retries=5)
    upload_url = init.get("args", {}).get("action")
    fields = init.get("args", {}).get("fields", {})
    asset_id = init.get("asset", {}).get("asset_id") or init.get("asset", {}).get("id")
    if not upload_url or not fields or not asset_id:
        raise RuntimeError(f"Failed to init media asset: {init}")

    with open(image_path, "rb") as fh:
        file_bytes = fh.read()
    # S3 expects the file field to be named 'file'
    _multipart_post(upload_url, fields, "file", (os.path.basename(image_path), file_bytes, guessed))

    # Poll asset status
    for _ in range(30):
        qs = urlencode({"id": asset_id})
        req = Request(
            f"https://oauth.reddit.com/api/media/asset.json?{qs}",
            headers={
                "User-Agent": REDDIT_UA,
                "Authorization": f"Bearer {bearer}",
                "Accept": "application/json",
            },
        )
        with urlopen(req, timeout=20) as resp:
            info = json.loads(resp.read().decode("utf-8"))
        state = info.get("asset", {}).get("state")
        if state == "succeeded":
            return asset_id
        if state == "failed":
            raise RuntimeError(f"Media processing failed: {info}")
        time.sleep(1)
    raise RuntimeError("Timed out waiting for media processing")


def submit_image_post(auth: RedditScriptAuth, subreddit: str, title: str, media_id: str, nsfw: bool = False, spoiler: bool = False, flair_id: str | None = None) -> Dict[str, Any]:
    bearer = auth.get_token()
    form = {
        "sr": subreddit,
        "kind": "image",
        "title": title,
        "media_id": media_id,
        "resubmit": True,
        "sendreplies": True,
        "nsfw": bool(nsfw),
        "spoiler": bool(spoiler),
        "api_type": "json",
    }
    if flair_id:
        form["flair_id"] = flair_id
    data = urlencode(form).encode()
    req = Request(
        "https://oauth.reddit.com/api/submit",
        data=data,
        headers={
            "User-Agent": REDDIT_UA,
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))

