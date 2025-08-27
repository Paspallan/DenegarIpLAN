from __future__ import annotations

import argparse

from .http import RedditHttpClient
from .subreddits import (
    analyze_posting_restrictions,
    fetch_automod_config,
    fetch_rules,
    search_subreddits,
)


def cmd_search(args: argparse.Namespace) -> None:
    with RedditHttpClient() as client:
        results = search_subreddits(client, query=args.query, limit=args.limit)
        print(f"Search: {args.query}")
        print("Subreddit\tSubs\t18+\tImages\tQuarantine\tTitle")
        for s in results:
            print(
                f"r/{s.name}\t{s.subscribers}\t{int(s.over18)}\t{int(s.allow_images)}\t{int(s.quarantine)}\t{s.title[:60]}"
            )


def cmd_inspect(args: argparse.Namespace) -> None:
    with RedditHttpClient() as client:
        rules = fetch_rules(client, subreddit=args.subreddit)
        automod = fetch_automod_config(client, subreddit=args.subreddit)
        restrictions = analyze_posting_restrictions(rules, automod)
        print(f"r/{args.subreddit} posting hints")
        for k, v in restrictions.items():
            print(f"- {k}: {v}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reddit_cli", description="Reddit Subreddit Explorer (read-only)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_search = sub.add_parser("search", help="Search subreddits")
    p_search.add_argument("--query", required=True, help="Search term")
    p_search.add_argument("--limit", type=int, default=10, help="Max results")
    p_search.set_defaults(func=cmd_search)

    p_inspect = sub.add_parser("inspect", help="Inspect subreddit rules")
    p_inspect.add_argument("--subreddit", required=True, help="Name without r/")
    p_inspect.set_defaults(func=cmd_inspect)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

