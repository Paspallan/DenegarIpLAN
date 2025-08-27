from __future__ import annotations

import argparse

from .http import RedditHttpClient
from .subreddits import (
    analyze_posting_restrictions,
    fetch_automod_config,
    fetch_rules,
    search_subreddits,
    fetch_subreddit_top_posts,
    filter_posts_for_candidates,
)
from .auth import RedditScriptAuth
from .crosspost import list_user_posts, filter_candidates_by_subreddit, crosspost
from .subdiscover import discover_image_subreddits
from .media import upload_image_and_get_media_id, submit_image_post
from .scheduler import SchedulerConfig, run_scheduler


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


def cmd_candidates_from_subreddit(args: argparse.Namespace) -> None:
    auth = RedditScriptAuth.from_env() if args.use_auth else None
    with RedditHttpClient() as client:
        posts = fetch_subreddit_top_posts(
            client,
            subreddit=args.subreddit,
            time_range=args.time_range,
            limit=args.limit,
            auth=auth,
        )
        cands = filter_posts_for_candidates(
            posts,
            min_score=args.min_score,
            older_than_days=args.older_than_days,
            require_image=True,
        )
        print("fullname\tsubreddit\tscore\tage_days\turl\ttitle")
        from time import time

        now = time()
        for p in cands:
            age_days = int((now - p.get("created_utc", 0)) / 86400)
            print(
                f"{p['fullname']}\t{p.get('subreddit')}\t{p.get('score',0)}\t{age_days}\t{p.get('url','')}\t{p.get('title','')[:80]}"
            )


def cmd_discover_image_subs(args: argparse.Namespace) -> None:
    subs = discover_image_subreddits(limit_per_query=args.limit_per_query)
    for s in subs:
        print(f"r/{s}")


def cmd_crosspost_from_subreddit(args: argparse.Namespace) -> None:
    auth = RedditScriptAuth.from_env()
    allowlist_raw = (args.author_allowlist or "").strip()
    allow_all = allowlist_raw.lower() == "all"
    allowlist = [a.strip().lower() for a in allowlist_raw.split(",") if a.strip()] if not allow_all else []
    if not allow_all and not allowlist:
        print("Author allowlist is empty; pass 'all' to include any author.")
        return
    with RedditHttpClient() as client:
        posts = fetch_subreddit_top_posts(
            client,
            subreddit=args.subreddit,
            time_range=args.time_range,
            limit=args.limit,
            auth=auth,
        )
        cands = filter_posts_for_candidates(
            posts,
            min_score=args.min_score,
            older_than_days=args.older_than_days,
            require_image=True,
        )
        # filter by author allowlist
        selected = cands if allow_all else [p for p in cands if (p.get("author", "").lower() in allowlist)]
        print(f"Selected {len(selected)} posts from r/{args.subreddit} to crosspost to r/{args.to_subreddit}")
        from time import sleep
        import json

        for p in selected:
            title = p.get("title", "")[:300]
            res = crosspost(
                fullname=f"t3_{p.get('id')}",
                dest_subreddit=args.to_subreddit,
                title=title,
                nsfw=bool(p.get("over_18", False)),
                spoiler=bool(p.get("spoiler", False)),
                flair_id=None,
                auth=auth,
                dry_run=not args.execute,
            )
            print(json.dumps({"source": p.get("permalink"), "result": res}, ensure_ascii=False))
            sleep(2)


def cmd_scheduler(args: argparse.Namespace) -> None:
    auth = RedditScriptAuth.from_env()
    pairs = []
    for part in args.routes.split(","):
        if ":" not in part:
            continue
        src, dst = part.split(":", 1)
        pairs.append((src.strip(), dst.strip()))
    if not pairs:
        print("No valid routes parsed. Use format 'source:dest,source2:dest2'")
        return
    cfg = SchedulerConfig(
        routes=pairs,
        min_score=args.min_score,
        older_than_days=args.older_than_days,
        time_range=args.time_range,
        limit_per_source=args.limit_per_source,
        min_wait_seconds=args.min_wait_seconds,
        max_wait_seconds=args.max_wait_seconds,
        max_posts=args.max_posts,
        state_file=args.state_file,
        execute=args.execute,
    )
    run_scheduler(cfg, auth)


def cmd_post_image(args: argparse.Namespace) -> None:
    auth = RedditScriptAuth.from_env()
    media_id = upload_image_and_get_media_id(auth, args.file)
    res = submit_image_post(auth, subreddit=args.subreddit, title=args.title, media_id=media_id, nsfw=args.nsfw, spoiler=args.spoiler)
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

    p_subc = sub.add_parser("candidates-from-subreddit", help="List candidates by subreddit top & old")
    p_subc.add_argument("--subreddit", required=True, help="Source subreddit")
    p_subc.add_argument("--min-score", type=int, default=500, help="Minimum score")
    p_subc.add_argument("--older-than-days", type=int, default=90, help="Minimum age in days")
    p_subc.add_argument("--time-range", default="all", choices=["day","week","month","year","all"], help="Top time range")
    p_subc.add_argument("--limit", type=int, default=100, help="Max posts to scan")
    p_subc.add_argument("--use-auth", action="store_true", help="Use OAuth to avoid 403")
    p_subc.set_defaults(func=cmd_candidates_from_subreddit)

    p_discover = sub.add_parser("discover-image-subs", help="Discover image-focused subreddits")
    p_discover.add_argument("--limit-per-query", type=int, default=20, help="Max results per keyword")
    p_discover.set_defaults(func=cmd_discover_image_subs)

    p_xsub = sub.add_parser(
        "crosspost-from-subreddit",
        help="Crosspost top old image posts from a subreddit (authors allowlist)",
    )
    p_xsub.add_argument("--subreddit", required=True, help="Source subreddit")
    p_xsub.add_argument("--to-subreddit", required=True, help="Destination subreddit")
    p_xsub.add_argument("--author-allowlist", required=True, help="Comma-separated authors you own")
    p_xsub.add_argument("--min-score", type=int, default=500, help="Minimum score")
    p_xsub.add_argument("--older-than-days", type=int, default=180, help=">= 6 months")
    p_xsub.add_argument("--time-range", default="all", choices=["year","all"], help="Top time range")
    p_xsub.add_argument("--limit", type=int, default=200, help="Max posts to scan")
    p_xsub.add_argument("--execute", action="store_true", help="Actually post (omit for dry-run)")
    p_xsub.set_defaults(func=cmd_crosspost_from_subreddit)

    p_sched = sub.add_parser("scheduler", help="Periodic crosspost with 1-2h random waits")
    p_sched.add_argument("--routes", required=True, help="Comma-separated list of source:dest pairs, e.g. 'carporn:carpics,EarthPorn:MostBeautiful'")
    p_sched.add_argument("--min-score", type=int, default=800)
    p_sched.add_argument("--older-than-days", type=int, default=180)
    p_sched.add_argument("--time-range", default="all", choices=["year","all"]) 
    p_sched.add_argument("--limit-per-source", type=int, default=100)
    p_sched.add_argument("--min-wait-seconds", type=int, default=3600)
    p_sched.add_argument("--max-wait-seconds", type=int, default=7200)
    p_sched.add_argument("--max-posts", type=int, default=10)
    p_sched.add_argument("--state-file", default="reddit_cli_state.json")
    p_sched.add_argument("--execute", action="store_true", help="Actually post (omit for dry-run)")
    p_sched.set_defaults(func=cmd_scheduler)

    p_img = sub.add_parser("post-image", help="Post a local image as native image post")
    p_img.add_argument("--subreddit", required=True)
    p_img.add_argument("--title", required=True)
    p_img.add_argument("--file", required=True)
    p_img.add_argument("--nsfw", action="store_true")
    p_img.add_argument("--spoiler", action="store_true")
    p_img.set_defaults(func=cmd_post_image)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

