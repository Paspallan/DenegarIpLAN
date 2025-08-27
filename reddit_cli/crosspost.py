from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .auth import RedditScriptAuth
from .http import HttpClientConfig, RedditHttpClient, REDDIT_UA


def _api_post(path: str, form: Dict[str, Any], auth: RedditScriptAuth) -> Dict[str, Any]:
    token = auth.get_token()
    url = f"https://oauth.reddit.com{path}"
    encoded = urlencode(form).encode()
    req = Request(
        url,
        data=encoded,
        headers={
            "User-Agent": REDDIT_UA,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def list_user_posts(username: str, limit: int, auth: RedditScriptAuth) -> List[Dict[str, Any]]:
    with RedditHttpClient(HttpClientConfig()) as client:
        data = client.get_json(f"/user/{username}/submitted.json", params={"limit": limit}, bearer=auth.get_token())
        return [c.get("data", {}) for c in data.get("data", {}).get("children", [])]


def filter_candidates_by_subreddit(posts: List[Dict[str, Any]], subreddit: str, min_score: int, older_than_days: int) -> List[Dict[str, Any]]:
    from time import time

    cutoff = time() - older_than_days * 86400
    results: List[Dict[str, Any]] = []
    for p in posts:
        if p.get("subreddit", "").lower() != subreddit.lower():
            continue
        if p.get("score", 0) < min_score:
            continue
        created_utc = p.get("created_utc", 0)
        if created_utc > cutoff:
            continue
        if p.get("over_18", False):
            # keep NSFW flag for later
            pass
        fullname = f"t3_{p.get('id')}"
        p["fullname"] = fullname
        results.append(p)
    return results


def crosspost(fullname: str, dest_subreddit: str, title: str, nsfw: bool, spoiler: bool, flair_id: Optional[str], auth: RedditScriptAuth, dry_run: bool = True) -> Dict[str, Any]:
    form = {
        "sr": dest_subreddit,
        "kind": "crosspost",
        "crosspost_fullname": fullname,
        "title": title,
        "resubmit": True,
        "nsfw": bool(nsfw),
        "spoiler": bool(spoiler),
        "api_type": "json",
    }
    if flair_id:
        form["flair_id"] = flair_id
    if dry_run:
        return {"dry_run": True, "form": form}
    return _api_post("/api/submit", form, auth)

