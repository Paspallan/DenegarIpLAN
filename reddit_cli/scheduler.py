from __future__ import annotations

import json
import os
import random
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .auth import RedditScriptAuth
from .http import RedditHttpClient
from .subreddits import fetch_subreddit_top_posts, filter_posts_for_candidates
from .crosspost import crosspost


@dataclass
class SchedulerConfig:
    routes: List[Tuple[str, str]]
    min_score: int = 800
    older_than_days: int = 180
    time_range: str = "all"
    limit_per_source: int = 100
    min_wait_seconds: int = 3600
    max_wait_seconds: int = 7200
    max_posts: int = 10
    state_file: str = "reddit_cli_state.json"
    execute: bool = False


def _load_state(path: str) -> Dict[str, List[str]]:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {"posted": []}
    return {"posted": []}


def _save_state(path: str, state: Dict[str, List[str]]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def run_scheduler(cfg: SchedulerConfig, auth: RedditScriptAuth) -> None:
    state = _load_state(cfg.state_file)
    seen: set[str] = set(state.get("posted", []))

    num_posted = 0
    routes = list(cfg.routes)

    with RedditHttpClient() as client:
        while num_posted < cfg.max_posts:
            random.shuffle(routes)
            did_post_this_round = False
            for source, dest in routes:
                posts = fetch_subreddit_top_posts(
                    client,
                    subreddit=source,
                    time_range=cfg.time_range,
                    limit=cfg.limit_per_source,
                    auth=auth,
                )
                cands = filter_posts_for_candidates(
                    posts,
                    min_score=cfg.min_score,
                    older_than_days=cfg.older_than_days,
                    require_image=True,
                )
                # prefer higher score first
                cands.sort(key=lambda p: p.get("score", 0), reverse=True)
                chosen = None
                for p in cands:
                    fullname = f"t3_{p.get('id')}"
                    if fullname in seen:
                        continue
                    chosen = p
                    break

                if not chosen:
                    continue

                title = chosen.get("title", "")[:300]
                res = crosspost(
                    fullname=f"t3_{chosen.get('id')}",
                    dest_subreddit=dest,
                    title=title,
                    nsfw=bool(chosen.get("over_18", False)),
                    spoiler=bool(chosen.get("spoiler", False)),
                    flair_id=None,
                    auth=auth,
                    dry_run=not cfg.execute,
                )
                print(json.dumps({
                    "source_sub": source,
                    "dest_sub": dest,
                    "post": {
                        "fullname": f"t3_{chosen.get('id')}",
                        "url": chosen.get("url"),
                        "title": title,
                        "score": chosen.get("score", 0),
                    },
                    "result": res,
                }, ensure_ascii=False))

                seen.add(f"t3_{chosen.get('id')}")
                state["posted"] = list(seen)
                _save_state(cfg.state_file, state)

                num_posted += 1
                did_post_this_round = True
                if num_posted >= cfg.max_posts:
                    break

                wait_s = random.randint(cfg.min_wait_seconds, cfg.max_wait_seconds)
                print(f"Waiting {wait_s} seconds before next post...")
                time.sleep(wait_s)

            if not did_post_this_round:
                # No candidates found; wait a shorter interval and try again
                wait_s = min(900, cfg.min_wait_seconds)
                print(f"No candidates found; waiting {wait_s} seconds and retrying...")
                time.sleep(wait_s)

