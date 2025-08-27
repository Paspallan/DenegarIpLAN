from __future__ import annotations

import argparse

from .http import RedditHttpClient
from .subreddits import (
    analyze_posting_restrictions,
    fetch_automod_config,
    fetch_rules,
    search_subreddits,
)
from .auth import RedditScriptAuth
from .crosspost import list_user_posts, filter_candidates_by_subreddit, crosspost


def cmd_search(args: argparse.Namespace) -> None:
    auth = None
    if args.use_auth:
        auth = RedditScriptAuth.from_env()
    with RedditHttpClient() as client:
        results = search_subreddits(client, query=args.query, limit=args.limit, auth=auth)
        print(f"Search: {args.query}")
        print("Subreddit\tSubs\t18+\tImages\tQuarantine\tTitle")
        for s in results:
            print(
                f"r/{s.name}\t{s.subscribers}\t{int(s.over18)}\t{int(s.allow_images)}\t{int(s.quarantine)}\t{s.title[:60]}"
            )


def cmd_inspect(args: argparse.Namespace) -> None:
    auth = None
    if args.use_auth:
        auth = RedditScriptAuth.from_env()
    with RedditHttpClient() as client:
        rules = fetch_rules(client, subreddit=args.subreddit, auth=auth)
        automod = fetch_automod_config(client, subreddit=args.subreddit, auth=auth)
        restrictions = analyze_posting_restrictions(rules, automod)
        print(f"r/{args.subreddit} posting hints")
        for k, v in restrictions.items():
            print(f"- {k}: {v}")


def cmd_candidates(args: argparse.Namespace) -> None:
    auth = RedditScriptAuth.from_env()
    posts = list_user_posts(username=args.from_user, limit=200, auth=auth)
    candidates = filter_candidates_by_subreddit(
        posts,
        subreddit=args.source_subreddit,
        min_score=args.min_score,
        older_than_days=args.older_than_days,
    )
    print("fullname\tsubreddit\tscore\tage_days\ttitle")
    from time import time

    now = time()
    for p in candidates:
        age_days = int((now - p.get("created_utc", 0)) / 86400)
        print(
            f"{p['fullname']}\t{p['subreddit']}\t{p.get('score', 0)}\t{age_days}\t{p.get('title', '')[:80]}"
        )


def cmd_crosspost(args: argparse.Namespace) -> None:
    auth = RedditScriptAuth.from_env()
    res = crosspost(
        fullname=args.fullname,
        dest_subreddit=args.to_subreddit,
        title=args.title,
        nsfw=args.nsfw,
        spoiler=args.spoiler,
        flair_id=args.flair_id,
        auth=auth,
        dry_run=not args.execute,
    )
    import json

    print(json.dumps(res, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reddit_cli", description="Reddit Subreddit Explorer (read-only)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_search = sub.add_parser("search", help="Search subreddits")
    p_search.add_argument("--query", required=True, help="Search term")
    p_search.add_argument("--limit", type=int, default=10, help="Max results")
    p_search.add_argument("--use-auth", action="store_true", help="Use OAuth credentials from env")
    p_search.set_defaults(func=cmd_search)

    p_inspect = sub.add_parser("inspect", help="Inspect subreddit rules")
    p_inspect.add_argument("--subreddit", required=True, help="Name without r/")
    p_inspect.add_argument("--use-auth", action="store_true", help="Use OAuth credentials from env")
    p_inspect.set_defaults(func=cmd_inspect)

    p_candidates = sub.add_parser("candidates", help="List crosspost candidates from your own posts")
    p_candidates.add_argument("--from-user", required=True, help="Your Reddit username")
    p_candidates.add_argument("--source-subreddit", required=True, help="Source subreddit to filter")
    p_candidates.add_argument("--min-score", type=int, default=100, help="Minimum score")
    p_candidates.add_argument("--older-than-days", type=int, default=60, help="Minimum age in days")
    p_candidates.set_defaults(func=cmd_candidates)

    p_cross = sub.add_parser("crosspost", help="Crosspost a specific post to a destination subreddit")
    p_cross.add_argument("--fullname", required=True, help="Fullname like t3_abcdef")
    p_cross.add_argument("--to-subreddit", required=True, help="Destination subreddit")
    p_cross.add_argument("--title", required=True, help="New title")
    p_cross.add_argument("--nsfw", action="store_true", help="Mark as NSFW")
    p_cross.add_argument("--spoiler", action="store_true", help="Mark as spoiler")
    p_cross.add_argument("--flair-id", default=None, help="Optional flair id")
    p_cross.add_argument("--execute", action="store_true", help="Actually post (omit for dry-run)")
    p_cross.set_defaults(func=cmd_crosspost)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

