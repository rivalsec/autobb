import os
from datetime import datetime
from typing import Dict, List, Any
import ipaddress
import collections
import logging


def file_to_list(file):
    fl = []
    if os.path.exists(file):
        with open(file, 'r') as f:
            for l in f.readlines():
                fl.append(l.rstrip())
    # return sorted(fl)
    return fl


def tsnow():
    '''
    Current string timestamp for folders and files
    %Y%m%d-%H%M
    '''
    return datetime.now().strftime('%Y%m%d-%H%M')


def remove_duplicates(obj_l:List[Dict], key):
    """Remove duplicates in obj_l by key field equal"""
    out_list = []
    for obj in obj_l:
        dup = next( (x for x in out_list if obj[key] == x[key]), None)
        if not dup:
            out_list.append(obj)
    return out_list


def extend_new_only(obj_l:List[Dict], add_l:List[Dict], key):
    """add in obj_l only new objects by key field"""
    for new_obj in add_l:
        if not next( (x for x in obj_l if x[key] == new_obj[key]) ,False):
            obj_l.append(new_obj)


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