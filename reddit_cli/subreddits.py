from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .http import RedditHttpClient


@dataclass
class SubredditMeta:
    name: str
    title: str
    subscribers: int
    over18: bool
    public_description: str
    allow_images: bool
    quarantine: bool


def search_subreddits(client: RedditHttpClient, query: str, limit: int = 10) -> List[SubredditMeta]:
    data = client.get_json(
        "/subreddits/search.json",
        params={"q": query, "limit": limit, "include_over_18": True},
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


def fetch_rules(client: RedditHttpClient, subreddit: str) -> Dict[str, Any]:
    data = client.get_json(f"/r/{subreddit}/about/rules.json")
    return data or {}


def fetch_automod_config(client: RedditHttpClient, subreddit: str) -> Optional[str]:
    # public automod can be fetched through wiki when exposed
    try:
        data = client.get_json(f"/r/{subreddit}/wiki/config/automoderator.json")
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

