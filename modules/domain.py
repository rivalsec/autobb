from typing import Dict, List
import logging
import re
import subprocess
from dnsgen import dnsgen
from utils.common import file_to_list, is_private_ip
import itertools
import random
from config import config, glob, alerter
import json
from functools import partial
import uuid
import os


def extract_prefixes(subdomains, scope_parents):
    """
    Extract full subdomain prefixes from all-scope discovered subdomains for cross-scope brute force.
    subdomains: list of dicts with 'host' and 'scope' fields
    scope_parents: {scope_name: [parent_domain_str, ...]}
    Returns set of prefix strings like 'api.v2', 'dev-api'.
    """
    prefixes = set()
    for sub in subdomains:
        host = sub['host'].lower()
        for parent in scope_parents.get(sub.get('scope', ''), []):
            suffix = '.' + parent
            if host.endswith(suffix) and host != parent:
                prefix = host[:-len(suffix)]
                if prefix:
                    prefixes.add(prefix)
                break
    return prefixes


def subdomain_isgood(d:str, parent:str):
    plen = len(parent) + 1
    if not d.endswith('.' + parent) and d != parent:
        return False
    if len(d) - plen > config['domain_filter']['max_len']:
        return False
    if len(d[:-plen].split('.')) > config['domain_filter']['max_sub']:
        return False
    return True


def brute_subs(domain, wordlist):
    '''
    return set with all possible subs with config['wordlist']
    '''
    wl = map(str.lower, file_to_list(wordlist))
    return set(map(lambda x: f"{x}.{domain}", wl))


def subfinder(domain:str):
    '''
    subfinder for 1 domain at a time
    '''
    cmd = config['subfinder']['cmd'].copy()
    cmd.extend(['-d', domain])
    out = set()
    subfinder_res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    #trash results filter
    for l in subfinder_res.stdout.splitlines():
        l = l.strip().lower()
        # trash subfinder  results filter
        if not subdomain_isgood(l, domain):
            continue
        out.add(l)
    return out


def subdomains_gen(domain, oldsubs, wordlist=None, alts_max=200000, alts_wordlen=2,
                   use_subfinder=True, scope_alts=None, brute_prefixes=None):
    '''
    only string subs
    subfinder + brute + alts
    '''
    #sub filter for exact parent domain
    subf = partial(subdomain_isgood, parent = domain)

    # 1) get all from subfinder
    subs = set()
    if use_subfinder:
        subs.update(filter(subf, subfinder(domain)))
        logging.info(f"{domain} +{len(subs)} subfinder")
    else:
        logging.info(f"{domain} subfinder skipped")

    subs.add(domain)
    #already reconed subdomains from database
    subs.update(filter(subf, map(str.lower, oldsubs)))

    if wordlist:
        # 2) brute subs
        subs_brute = set(filter(subf, brute_subs(domain, wordlist)))
        logging.info(f"{domain} +{len(subs_brute)} from {wordlist}")
        subs.update(subs_brute)

    if brute_prefixes:
        subs_prefix = set(filter(subf, (f"{p}.{domain}" for p in brute_prefixes)))
        logging.info(f"{domain} +{len(subs_prefix)} from all-scope prefixes")
        subs.update(subs_prefix)

    # 3) harvested subs from previous-session response harvests
    harv_root = config.get('harvested_dir', 'harvested')
    harvested = set()
    if os.path.isdir(harv_root):
        files = 0
        for entry in sorted(os.listdir(harv_root)):
            sf = os.path.join(harv_root, entry, 'subs.txt')
            if os.path.isfile(sf):
                harvested.update(filter(subf, map(str.lower, file_to_list(sf))))
                files += 1
        if harvested:
            logging.info(f"{domain} +{len(harvested)} from harvested subs ({files} files in {harv_root}/)")
            subs.update(harvested)

    # make alts from old subs + harvested + in-scope subs from other domains (real observed hostnames)
    if alts_max and alts_max > 0:
        alts_input = list(set(oldsubs) | harvested | set(scope_alts or []))
        random.shuffle(alts_input)
        subs_alts_gen = dnsgen.generate(alts_input, wordlen=alts_wordlen, fast=False)
        subs_alts = set(itertools.islice(filter(subf, subs_alts_gen), alts_max))
        logging.info(f"{domain} +{len(subs_alts)} alt subdomains from {len(alts_input)} seeds (dnsgen wordlen={alts_wordlen} fast=False)")
        subs.update(subs_alts)

    logging.info(f"{domain} {len(subs)} in total subdomains to check")
    return subs


def shuffledns(domains, domain):
    cmd = config['shuffledns']['cmd'].copy()
    cmd.extend(['-d', domain])
    stdin_text = "\n".join(domains)+'\n'
    logging.info(' '.join(cmd))
    out = set()
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=stdin_text, text=True)
    for l in res.stdout.splitlines():
        l = l.strip().lower()
        out.add(l)
    return out


def dnsx(domains):
    cmd = config['dnsx']['cmd'].copy()
    stdin_text = "\n".join(domains)+'\n'
    logging.info(f"{len(domains)} domains | " + ' '.join(cmd))
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=stdin_text, text=True)
    domains = [json.loads(x) for x in res.stdout.splitlines()]
    domains = list(filter(lambda d: 'a' in d, domains))
    revdns(domains)
    return domains


def revdns(domains):
    """ add ptr from a to each domain in list"""
    cmd = config['dnsx']['cmd_ptr'].copy()
    d_ips = set()
    for d in domains:
        for a in d['a']:
            if not is_private_ip(a):
                d_ips.add(a)
    stdin_text = "\n".join(d_ips)+'\n'
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=stdin_text, text=True)
    logging.info(' '.join(cmd))
    ptrs = [json.loads(x) for x in res.stdout.splitlines()]
    for d in domains:
        ptr = set()
        for p in ptrs:
            if 'ptr' in p and p['host'] in d['a']:
                ptr.update(map(str.lower, p['ptr']))
        if ptr:
            d['a_rev'] = list(ptr)


def puredns(domains, timeout = 120):
    '''
    puredns (resolve + wildcard filter) on input iterable
    '''
    write_out_file = f"{glob.tmp_dir}/purednsout_{str(uuid.uuid4())}"
    in_file = f"{glob.tmp_dir}/purednsin_{str(uuid.uuid4())}"
    cmd = config['puredns']['cmd'].copy()
    cmd.insert(2, in_file)
    cmd.extend(['--write', write_out_file])
    c = 0
    with open(in_file, 'w') as f:
        for d in domains:
            f.write(f"{d}\n")
            c += 1
    logging.info(f"{c} domains | " + ' '.join(cmd))
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                            text=True, errors="backslashreplace",
                            timeout=timeout * 60)
        if res.stderr:
            logging.error(res.stderr)
    except subprocess.TimeoutExpired:
        logging.error("Puredns timeout!")
    results = file_to_list(write_out_file)
    results = map(str.lower, results)
    # delete in files because of size
    os.remove(in_file)
    # only uniq
    return list(set(results))


def issub(sub, domain):
    if sub == domain:
        return True
    if sub.endswith('.' + domain):
        return True
    return False


def domain_purespray(domains, old_subs, alts_max, wordlist, timeout=120, use_subfinder=True,
                     domain_to_scope=None, scope_alts_map=None, all_scope_prefixes=None) -> List[Dict]:
    """
    spray puredns check of random subs an set scope to them,
    return list of Dict {'host', 'parent_host','scope'??}
    """
    chsubs = list()
    for d in domains:
        domain_subs = list(filter(lambda x: subdomain_isgood(x['host'], d), old_subs))
        oldsubs_list = list([ x['host'] for x in domain_subs ])
        d_scope = (domain_to_scope or {}).get(d)
        d_scope_alts = list((scope_alts_map or {}).get(d_scope, []))
        chsubs.extend(subdomains_gen(d, oldsubs_list, wordlist, alts_max=alts_max,
                                     use_subfinder=use_subfinder,
                                     scope_alts=d_scope_alts,
                                     brute_prefixes=all_scope_prefixes))
    #pure subs shuffle !!
    random.shuffle(chsubs)
    puresubs = puredns(chsubs, timeout)
    subobjs = []
    for d in [dict(host=x,parent_host="unknown") for x in puresubs]:
        #set parent (for weird calc)
        for p in domains:
            if issub(d['host'], p):
                d['parent_host'] = p
        subobjs.append(d)
    return subobjs
