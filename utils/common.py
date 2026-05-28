import os
from datetime import datetime
from typing import Dict, List, Any
import ipaddress
import collections
import logging
import re


def file_to_list(file):
    fl = []
    if os.path.exists(file):
        with open(file, 'r') as f:
            for l in f:
                fl.append(l.rstrip())
    return fl


def file_lines_count(file):
    c = 0
    with open(file, 'r') as f:
        for l in f:
            c += 1
    return c


def tsnow():
    '''
    Current string timestamp for folders and files
    %Y%m%d-%H%M
    '''
    return datetime.now().strftime('%Y%m%d-%H%M')


def is_private_ip(ip):
    ipobj = ipaddress.IPv4Address(ip)
    if ipobj in ipaddress.IPv4Network('10.0.0.0/8'):
        return True
    if ipobj in ipaddress.IPv4Network('172.16.0.0/12'):
        return True
    if ipobj in ipaddress.IPv4Network('192.168.0.0/16'):
        return True
    if ipobj in ipaddress.IPv4Network('127.0.0.0/8'):
        return True
    return False


def domain_inscope(domain:str, scope:Dict[str,Any]):
    for p in scope["domains"]:
        if domain == p:
            return True
        for refilter in scope["sub_refilters"]:
            if re.search(refilter, domain):
                return False
        if scope["subs_recon"] and domain.endswith("." + p):
            return True
    return False


def domains_setscope(domains:Dict[str,Any], scopes:Dict[str,Any]):
    for d in domains:
        d["scope"] = "unknown"
        for s in scopes:
            if domain_inscope(d["host"], s):
                d["scope"] = s["name"]
                break


def threshold_filter(items:Dict[str,Any], item_key:str, threshold:int):
    filtred = []
    wc = collections.Counter([x[item_key] for x in items])
    for wkey in [k for k in wc if wc[k] > threshold]:
        logging.info(f"{wkey} count {wc[wkey]} is weird")
        filtred.extend([x for x in items if x[item_key] == wkey])
        items = list([x for x in items if x[item_key] != wkey])

    return items, filtred


def prefix_cluster_filter(items, prefix_len, group_max,
                          group_keys=('host', 'status_code', 'words', 'lines'),
                          path_key='path'):
    """Collapse over-sized prefix clusters into a single representative.

    For each unique combination of group_keys plus the first prefix_len chars
    of the path (case-insensitive, leading slash stripped), if the bucket has
    more than group_max items only the shortest path is kept; the rest are
    returned as 'filtered'. Catches wordlist-style wildcards like
    admin/administrator/adminpanel all responding with same status+words+lines.
    """
    groups = collections.defaultdict(list)
    for it in items:
        path = (it.get(path_key) or '').lstrip('/').lower()
        prefix = path[:prefix_len]
        bucket = tuple(it.get(k) for k in group_keys) + (prefix,)
        groups[bucket].append(it)

    keep, filtred = [], []
    for bucket, bucket_items in groups.items():
        if len(bucket_items) > group_max:
            bucket_items.sort(key=lambda x: len(x.get(path_key) or ''))
            rep = bucket_items[0]
            keep.append(rep)
            filtred.extend(bucket_items[1:])
            logging.info(
                f"prefix cluster {bucket} size {len(bucket_items)} collapsed to {rep.get(path_key)}"
            )
        else:
            keep.extend(bucket_items)
    return keep, filtred


def scope_update(arr, scope_name):
    for item in arr:
        item['scope'] = scope_name


class uniq_list(list):

    def __init__(self, key:str) -> None:
        self._key = key
        self._seenkees = set()

    def extend(self, inl):
        for obj in inl:
            if self._isuniq(obj):
                super().append(obj)

    def append(self, obj) -> None:
        if self._isuniq(obj):
            super().append(obj)

    def _isuniq(self, obj):
        iv = obj[self._key]
        if iv not in self._seenkees:
            self._seenkees.add(iv)
            return True
        

def hit_tostr(x):
    return f'{x["scope"]}: {x.get("matched-at","")} [{x["info"]["severity"]}] {x["template-id"]} {x.get("matcher-name","")} {x.get("extracted-results","")}'
