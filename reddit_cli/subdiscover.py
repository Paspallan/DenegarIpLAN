from __future__ import annotations

from typing import List

from .auth import RedditScriptAuth
from .http import RedditHttpClient
from .subreddits import search_subreddits


IMAGE_KEYWORDS = [
    "pics",
    "photos",
    "images",
    "wallpaper",
    "cars",
    "carporn",
    "earthporn",
    "cityporn",
    "food",
    "cats",
    "dogs",
    "architecture",
    "art",
]


def discover_image_subreddits(limit_per_query: int = 20) -> List[str]:
    candidates = set()
    with RedditHttpClient() as client:
        for kw in IMAGE_KEYWORDS:
            subs = search_subreddits(client, query=kw, limit=limit_per_query)
            for s in subs:
                name = s.name.lower()
                text = f"{s.title} {s.public_description}".lower()
                if any(k in name for k in ["pics","porn","images","photos","wallpaper"]) or any(
                    k in text for k in ["image","photo","wallpaper","gallery"]
                ):
                    if s.allow_images and not s.quarantine:
                        candidates.add(name)
    return sorted(candidates)

