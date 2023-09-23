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


def subdomains_gen(domain, oldsubs, wordlist = None, alts_max=200000, alts_wordlen=2):
    '''
    only string subs
    subfinder + brute + alts
    '''
    #sub filter for exact parent domain
    subf = partial(subdomain_isgood, parent = domain)

    # 1) get all from subfinder
    subs = set()
    logging.info(f"{domain} ищем сабдомены subfinder...")
    subs.update(filter(subf, subfinder(domain)))
    logging.info(f"{domain} subfinder {len(subs)} шт.")

    subs.add(domain)
    #already reconed subdomains from database
    subs.update(filter(subf, map(str.lower, oldsubs)))

    if wordlist:
        # 2) brute subs
        subs_brute = set(filter(subf, brute_subs(domain, wordlist)))
        logging.info(f"{domain} сгенерировали {len(subs_brute)} шт. с помощью {wordlist}")
        subs.update(subs_brute)

    # make alts from old subs
    if alts_max and alts_max > 0:        
        random.shuffle(oldsubs)
        subs_alts_gen = dnsgen.generate(oldsubs, wordlen=alts_wordlen, fast=False)
        subs_alts = set(itertools.islice(filter(subf, subs_alts_gen), alts_max))
        logging.info(f"{domain} сгенерировали из {len(oldsubs)} живых {len(subs_alts)} алтернативных (dnsgen wordlen={alts_wordlen} fast=False)")
        subs.update(subs_alts)

    logging.info(f"{domain} итого сгенерили {len(subs)} сабов")
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


def domain_purespray(domains, old_subs, alts_max, wordlist, timeout=120) -> List[Dict]:
    """
    spray puredns check of random subs an set scope to them, 
    return list of Dict {'host', 'parent_host','scope'??}
    """
    chsubs = list()
    for d in domains:
        domain_subs = list(filter(lambda x: subdomain_isgood(x['host'], d), old_subs))
        oldsubs_list = list([ x['host'] for x in domain_subs ])
        chsubs.extend(subdomains_gen(d,oldsubs_list, wordlist, alts_max=alts_max ))
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
