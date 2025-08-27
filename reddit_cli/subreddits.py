from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .http import RedditHttpClient
from .auth import RedditScriptAuth


@dataclass
class SubredditMeta:
    name: str
    title: str
    subscribers: int
    over18: bool
    public_description: str
    allow_images: bool
    quarantine: bool


def search_subreddits(client: RedditHttpClient, query: str, limit: int = 10, auth: Optional[RedditScriptAuth] = None) -> List[SubredditMeta]:
    bearer = auth.get_token() if auth else None
    data = client.get_json(
        "/subreddits/search.json",
        params={"q": query, "limit": limit, "include_over_18": True},
        bearer=bearer,
    )
    results: List[SubredditMeta] = []
    for child in data.get("data", {}).get("children", []):
        d = child.get("data", {})
        results.append(
            SubredditMeta(
                name=d.get("display_name", ""),
                title=d.get("title", ""),
                subscribers=d.get("subscribers", 0),
                over18=d.get("over18", False),
                public_description=d.get("public_description", ""),
                allow_images=d.get("allow_images", False),
                quarantine=d.get("quarantine", False),
            )
        )
    return results


def fetch_rules(client: RedditHttpClient, subreddit: str, auth: Optional[RedditScriptAuth] = None) -> Dict[str, Any]:
    bearer = auth.get_token() if auth else None
    data = client.get_json(f"/r/{subreddit}/about/rules.json", bearer=bearer)
    return data or {}


def fetch_automod_config(client: RedditHttpClient, subreddit: str, auth: Optional[RedditScriptAuth] = None) -> Optional[str]:
    # public automod can be fetched through wiki when exposed
    try:
        bearer = auth.get_token() if auth else None
        data = client.get_json(f"/r/{subreddit}/wiki/config/automoderator.json", bearer=bearer)
        # wiki returns { data: { content_md: "..." } }
        return data.get("data", {}).get("content_md", None)
    except Exception:
        return None


def analyze_posting_restrictions(rules_json: Dict[str, Any], automod_md: Optional[str]) -> Dict[str, Any]:
    restrictions: Dict[str, Any] = {
        "requires_account_age_days": None,
        "requires_karma": None,
        "requires_flair": False,
        "no_reposts": False,
        "nsfw_only": False,
    }

    for rule in rules_json.get("rules", []):
        desc = (rule.get("description", "") or "").lower()
        short = (rule.get("short_name", "") or "").lower()
        text = f"{short}\n{desc}"
        if "repost" in text:
            restrictions["no_reposts"] = True
        if "flair" in text:
            restrictions["requires_flair"] = True
        if "nsfw" in text and ("only" in text or "must" in text):
            restrictions["nsfw_only"] = True

    if automod_md:
        lowered = automod_md.lower()
        # naive extraction of common patterns
        if "account_age" in lowered:
            restrictions["requires_account_age_days"] = 1
        if "link_karma" in lowered or "comment_karma" in lowered or "total_karma" in lowered:
            restrictions["requires_karma"] = 1

    return restrictions


def fetch_subreddit_top_posts(
    client: RedditHttpClient,
    subreddit: str,
    time_range: str = "all",
    limit: int = 50,
    auth: Optional[RedditScriptAuth] = None,
) -> List[Dict[str, Any]]:
    bearer = auth.get_token() if auth else None
    data = client.get_json(
        f"/r/{subreddit}/top.json", params={"t": time_range, "limit": limit}, bearer=bearer
    )
    return [c.get("data", {}) for c in data.get("data", {}).get("children", [])]


def is_image_post(post: Dict[str, Any]) -> bool:
    url = (post.get("url") or "").lower()
    domain = (post.get("domain") or "").lower()
    post_hint = (post.get("post_hint") or "").lower()
    is_gallery = bool(post.get("is_gallery"))
    if post_hint == "image" or is_gallery:
        return True
    if domain in {"i.redd.it", "i.imgur.com"}:
        return True
    if any(url.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".gif"]):
        return True
    return False


def filter_posts_for_candidates(
    posts: List[Dict[str, Any]],
    min_score: int,
    older_than_days: int,
    require_image: bool = True,
) -> List[Dict[str, Any]]:
    from time import time

    cutoff = time() - older_than_days * 86400
    results: List[Dict[str, Any]] = []
    for p in posts:
        if p.get("score", 0) < min_score:
            continue
        created_utc = p.get("created_utc", 0)
        if created_utc > cutoff:
            continue
        if require_image and not is_image_post(p):
            continue
        p["fullname"] = f"t3_{p.get('id')}"
        results.append(p)
    return results

