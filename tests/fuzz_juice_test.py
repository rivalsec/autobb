#!/usr/bin/env python3
"""Replay the httpfuzz filter+juicer chain against existing http_paths rows.

Reads recent http_paths from MongoDB (no ffuf), runs the same prefilters and
juicer the live workflow uses (subs.py:245-262), and prints the result sorted by
weight in the notification line format. Tweak juicy.py / httpfuzz filter config
and rerun to see the effect.
"""
import argparse
import collections
from datetime import datetime, timedelta

from config import config, db, scopes
from juicy import juicer, path_unusual_status, have_diffs
from utils.common import prefix_cluster_filter, threshold_filter


def path_status_200(http_path, scopes, filters, weight=5):
    """200 OK on a fuzzed path = a real resource was found."""
    if http_path.get('status_code') == 200:
        return " !s200", weight


def path_4xx_to_200(http_path, scopes, filters, weight=10):
    """status_code flipped from 4xx (forbidden/missing) to 200 -> newly exposed."""
    if http_path.get('status_code') != 200:
        return
    prior = list(http_path.get('_diffs_history', []))
    if 'diffs' in http_path:               # transient diff present only in live runs
        prior.append(http_path['diffs'])
    for diff in prior:
        old = diff.get('status_code')
        if isinstance(old, int) and 400 <= old < 500:
            return " !4xx>200", weight


# local override: drop path_juicy_keyword (the !key juicer); add 200-OK weight
http_paths_validators = [path_unusual_status, path_status_200, path_4xx_to_200, have_diffs]


def scope_equal_filter(items, threshold, keys=('scope', 'status_code', 'words', 'lines')):
    """Drop the whole bucket of paths that share (scope, status_code, words,
    lines) when it has more than `threshold` items. Catches scope-wide generic
    responses (e.g. a soft-404 served identically across many hosts/paths).
    Drops every item in an oversized bucket (no representative kept), like
    threshold_filter."""
    groups = collections.defaultdict(list)
    for it in items:
        groups[tuple(it.get(k) for k in keys)].append(it)
    keep, filtred = [], []
    for bucket_items in groups.values():
        if len(bucket_items) > threshold:
            filtred.extend(bucket_items)
        else:
            keep.extend(bucket_items)
    return keep, filtred


def fmt(x):
    return (f"{x['scope']}: {x.get('full_url') or x['url'] + x['path']} "
            f"[{x['status_code']}] {x['content_length']}b {x['words']}w {x['lines']}l"
            f"{(' -> ' + x['redirect']) if x.get('redirect') else ''}{x['juicy_info']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--days', type=int, default=2, help='look back this many days by add_date')
    ap.add_argument('--scope', help='restrict to a single scope name')
    ap.add_argument('--min-weight', type=int, default=0, help='hide hits below this juicy_weight')
    ap.add_argument('--scope-equal-max', type=int, default=5,
                    help='drop buckets sharing (scope,status,words,lines) larger than this')
    args = ap.parse_args()

    query = {'add_date': {'$gte': datetime.now() - timedelta(days=args.days)}}
    if args.scope:
        query['scope'] = args.scope
    hits = list(db['http_paths'].find(query))
    print(f"loaded {len(hits)} http_paths from last {args.days} day(s)"
          f"{' scope=' + args.scope if args.scope else ''}")

    hits, clustered = prefix_cluster_filter(
        hits,
        config['httpfuzz']['prefix_cluster_len'],
        config['httpfuzz']['prefix_cluster_max'],
    )
    hits, scope_equal = scope_equal_filter(hits, args.scope_equal_max)
    hits, weird = threshold_filter(hits, 'url', config['httpfuzz']['paths_weird_threshold'])
    print(f"prefix_cluster_filter dropped {len(clustered)}, "
          f"scope_equal_filter dropped {len(scope_equal)}, "
          f"threshold_filter dropped {len(weird)} -> {len(hits)} remain")

    juicer(hits, http_paths_validators, scopes, config['juicer_filters'])
    hits.sort(key=lambda x: x['juicy_weight'], reverse=True)

    shown = 0
    for x in hits:
        if x['juicy_weight'] < args.min_weight:
            continue
        # print(f"[w{x['juicy_weight']}] {fmt(x)}")
        print(f"{fmt(x)} [w{x['juicy_weight']}]")
        shown += 1
    print(f"\nshown {shown}/{len(hits)} (min-weight={args.min_weight})")


if __name__ == '__main__':
    main()
