#!/usr/bin/env python3
from typing import Dict, List
import os
import random
import logging
import argparse
from datetime import datetime
import shutil
import compare
import math
import ipaddress
import traceback
import time
from juicy import juicer, http_probes_validators, domain_validators
from db_bulk import db_get_modified_bulk
from modules.domain import dnsx, subdomain_isgood, domain_purespray
from modules.http import httprobes
from modules.port import portprobes
from modules.vulns import nuclei_active, nuclei_passive
from utils.common import extend_new_only, remove_duplicates, domains_setscope, threshold_filter


def notify_block(title, items:list, lines_num:int = None):
    out = f"{title}\n"
    if len(items):
        if lines_num and len(items) > lines_num:
            out += "\n".join(items[:lines_num]) + "\n...\n"
        else:
            out += "\n".join(items) + '\n'
    return out


def severity_sort(nuclei_res_l):
    '''
    sort by severity [critical] [high] [medium] [low] [info]
    '''
    skeys = ['critical', 'high', 'medium', 'low', 'unknown', 'info']
    nuclei_res_l.sort( key=lambda x: [i for i,v in enumerate(skeys) if x['info']['severity'] == v] )


def cli_args():
    parser = argparse.ArgumentParser(description='$$$')
    parser.add_argument('--dns-brute', action='store_true', help='bruteforce subdomains with wordlist')
    parser.add_argument('--dns-alts', action='store_true', help='try alternative permutated subdomains, based on finded')
    parser.add_argument('--workflow-olds', action='store_true', help='httpprobe old subs to find changes, else check only new subdomains')
    parser.add_argument('--ports', action='store_true', help='scan ports top 1000 - on new top 100 on old')
    parser.add_argument('--ports-olds', action='store_true', help='rescan ports top 100 on old probes')
    parser.add_argument('--nuclei', action='store_true', help='nuclei tests on new')
    parser.add_argument('--passive', action='store_true', help='passive nuclei checks')
    args = parser.parse_args()
    return args


def db_get_modified_domains (items, db_collection):
    return db_get_modified_bulk( items, db_collection, ['host'], ['host','a','a_rev','cname','scope'], compare.domain )


def db_get_modified(items, db_collection, key_fields, fields, compare_func):
    """returns modified(by compare_fields) an new items, update

    key_field - key for find same item in db,
    fields - use only these to insert and update items in db collection,
    db_collection - mongodb collection,
    compare_fields - fields to find modified items
    """
    out = []
    #kostili ) for back comp
    if not isinstance(key_fields, list):
        key_fields = [key_fields]

    for item in items:
        update_query = { '$set':{'last_alive': datetime.now()}, '$unset': {} }
        #construct update query
        for f in fields:
            if f in item:
                update_query['$set'][f] = item[f]
            else:
                update_query['$unset'][f] = ''
        #construct find query
        find_q = {}
        for key_field in key_fields:
            find_q[key_field] = item.get(key_field)

        for i in range(5):
            try:
                old_item = db_collection.find_one_and_update(find_q, update_query)
                db_error = None
                break
            except Exception as e:
                logging.error(f"{str(e)} try {i}")
                db_error = e
                time.sleep(2)
        
        if db_error:
            raise db_error

        if not old_item:
            insert_item = {}
            # for key_field in key_fields:
            #     insert_item = { key_field: item[key_field] } #wtf in fields same
            insert_item['add_date'] = insert_item['last_alive'] = datetime.now()
            for f in fields:
                if f in item:
                    insert_item[f] = item[f]
            out.append(item)
            res = db_collection.insert_one(insert_item)
            item['_id'] = res.inserted_id
        else:
            # find changed based on compare_func
            item['_id'] = old_item['_id']
            # _diffs_history init
            if '_diffs_history' in old_item:
                item['_diffs_history'] = old_item['_diffs_history']

            # at first compare without history update diffs if needed
            comp_res = compare_func(item, old_item)
            if not comp_res['equal']:
                #write old values from diffs to _diffs_history and update _diffs_history in DB
                if not '_diffs_history' in old_item:
                    item['_diffs_history'] = []
                # add onlly uniq
                if not comp_res['diffs'] in item['_diffs_history']:
                    item['_diffs_history'].append(comp_res['diffs'])
                    #update 
                    db_collection.update_one({'_id': item['_id']}, {'$set': {'_diffs_history': item['_diffs_history']}})

                # second stage compare with history Not simple compare because of tld sub filters
                comp_res_history = compare_func(item, old_item, True)
                if not comp_res_history['equal']:
                    item['diffs'] = comp_res['diffs']
                    out.append(item)

    return out


def small_scopes_slice(items, scopes, max):
    """ small scopes at first [][:max]shuffle """
    out = []
    out_items = []
    for scope_name in [x['name'] for x in scopes]:
        scope_items = [x for x in items if x['scope'] == scope_name]
        if len(scope_items) > 0:
            out.append( (scope_name, scope_items) )
    out.sort( key=lambda x: len(x[1]) )
    for s in out:
        out_items.extend(s[1])
    out_items = out_items[:max]
    random.shuffle(out_items)
    return out_items[:max]


def sites_equal_filter(sites):
    filter_keys = ['scope', 'status_code', 'title', 'content_length']
    # webserver?, technologies?
    uniq_sites = []
    out_sites = []
    for site in sites:
        fsite = {k : site.get(k, None) for k in filter_keys}
        if fsite not in uniq_sites:
            uniq_sites.append(fsite)
            out_sites.append(site)
    return out_sites


def sites_workflow(domains, httpx_threads=1):
    '''
    http probes -> find_new -> nuclei

    domains - list of subdomains/ports objects to check
    '''
    # random order for httpx
    random.shuffle(domains)
    logging.info(f"ищем сайты на {len(domains)} хостах(хост-порт) ({httpx_threads} потоков)")
    if args.passive:
        httprobe_res, _ = httprobes(domains, threads=httpx_threads, savedir=glob.httprobes_savedir)
    else:
        httprobe_res, _ = httprobes(domains, threads=httpx_threads)

    #new probes
    up_fields = ["url", "scheme","port","body_sha256","header_sha256","a","cnames","input", "location","title","webserver",
                "content_type","method","host","content_length","words","lines","chain_status_codes","status_code","tls_grab",
                "response_time","technologies","final_url",'scope']
    sites_new = db_get_modified(httprobe_res, db['http_probes'], ['url'], up_fields, compare.http_probe)
    #todo filter equal by scope same code,title, content-lenght?, technologies?
    sites_new = sites_equal_filter(sites_new)

    logging.info(f"нашли {len(sites_new)} новых сайтов")

    if len(sites_new) == 0:
        return

    juicer(sites_new, http_probes_validators, scopes, config['juicer_filters'])
    notify_by_weight(sites_new, scopes, "probe(s)", lambda x: f"{x['url']} [{x['status_code']}] [{x.get('title','')}]{x['juicy_info']}", False, True)

    if not args.nuclei:
        return
    
    sites_new = small_scopes_slice(sites_new, scopes, config['nuclei_one_time_max'])

    # new site fingerpints nuclei scan
    nuclei_hits = nuclei_active(config['nuclei']['cmd'], sites_new)
    #new nuclei hits
    up_fields = ["template-id","info","type","matcher-name","host","matched-at","meta","extracted-results","interaction","scope","curl-command"]
    index_fields = ["template-id","matcher-name","matched-at"]
    nuclei_hits_new = db_get_modified(nuclei_hits, db['nuclei_hits'], index_fields, up_fields, compare.nuclei_hit)
    severity_sort(nuclei_hits)
    notify_msg = "\n".join( [ f'{x["scope"]}: {x["matched-at"]} [{x["info"]["severity"]}] {x["template-id"]} {x.get("matcher-name","")} {x.get("extracted-results","")}' for x in nuclei_hits ] )
    alerter.notify(notify_msg)


def passive_workflow(all_http_probes):
    for scan_type in ['passive']:
        passive_results = nuclei_passive(glob.httprobes_savedir, all_http_probes, scan_type)
        
        #new nuclei hits
        up_fields = ["template-id","info","type","matcher-name","host","port","path","matched-at","meta","extracted-results","scope"]
        index_fields = ["template-id","matcher-name","host"]
        nuclei_hits_new = db_get_modified(passive_results, db['nuclei_passive_hits'], index_fields, up_fields, compare.nuclei_hit)

        severity_sort(nuclei_hits_new)
        notify_msg = f"Passive scan at {glob.httprobes_savedir}:\n"
        notify_msg += "\n".join( [ f'{x["scope"]}: {x["host"]} [{x["info"]["severity"]}] {x["template-id"]} {x.get("matcher-name","")} {x.get("extracted-results","")}' for x in nuclei_hits_new ] )
        alerter.notify(notify_msg)


def notify_ports(port_probes):
    notify_lines = []
    uniq_ips =  set([x['ip'] for x in port_probes])
    for ip in uniq_ips:
        ip_ports = list(set([ int(x['port']) for x in port_probes if x['ip']==ip ]))
        ip_ports.sort()
        ip_hosts = list(set([ x['host'] for x in port_probes if x['ip']==ip ]))
        notify_lines.append(f"{ip} {ip_hosts} {ip_ports}")
    
    if notify_lines:
        msg = notify_block(f"+{len(port_probes)} new ports.", notify_lines)
        alerter.notify(msg)


def notify_by_weight(items:List, scopes, title_suffix, print_item_func, max_scope_items = 5, show_not_juicy = False):
    """notify on new or modified items, group by scope, sort by scope juicy weight (mute)"""
    items.sort(key=lambda x: x['juicy_weight'], reverse=True)
    notify_blocks = []
    for scope_name in [s['name'] for s in scopes]:
        notify_lines = []
        scope_subs = [x for x in items if x['scope']==scope_name]
        scope_subs_len = len(scope_subs)
        scope_weight = 0
        for x in scope_subs:
            if x['juicy_weight'] or show_not_juicy:
                scope_weight += x['juicy_weight']
                notify_lines.append("- " + print_item_func(x))
        if scope_subs_len > 0:
            scope_msg = notify_block(f"{scope_name}:{scope_weight} +{len(scope_subs)} {title_suffix}.", notify_lines, max_scope_items)
            #log all lines!
            logging.info(notify_block(f"{scope_name}:{scope_weight} +{len(scope_subs)} {title_suffix}.", notify_lines))
            notify_blocks.append( {'msg': scope_msg, 'weight': scope_weight, 'subs_len':scope_subs_len, } )

    # notify_blocks.sort(key=lambda x: x['weight'], reverse=True)
    notify_blocks.sort(key=lambda x: x['subs_len'])
    if notify_blocks:
        notify_msg = "".join( [ x['msg'] for x in notify_blocks ] )
        alerter.notify(notify_msg)


def new_ports_workflow(port_items):
    logging.info(f"ищем язвимости на {len(port_items)} новых портах")
    #non http ports nuclei scan
    for h in port_items:
        h['url'] = f"{h['host']}:{h['port']}"
    nuclei_hits = nuclei_active(config['nuclei']['network_cmd'], port_items)
    up_fields = ["template-id","info","type","matcher-name","host","matched-at","meta","extracted-results","interaction","scope","curl-command"]
    index_fields = ["template-id","matcher-name","matched-at"]
    nuclei_hits_new = db_get_modified(nuclei_hits, db['nuclei_hits'], index_fields, up_fields, compare.nuclei_hit)
    severity_sort(nuclei_hits_new)
    notify_msg = "\n".join( [ f'{x["scope"]}: {x["matched-at"]} [{x["info"]["severity"]}] {x["template-id"]} {x.get("matcher-name","")} {x.get("extracted-results","")}' for x in nuclei_hits_new ] )
    alerter.notify(notify_msg)


def hosts_from_cidrs_ips(scope):
    hosts = []
    for cidr in scope.get('cidr', []):
        hosts.extend( [ {'host':str(ip), 'scope': scope['name']} for ip in ipaddress.IPv4Network(cidr)] )
    
    #ips
    hosts.extend( [ {'host':ip, 'scope': scope['name']} for ip in scope.get('ips', []) ] )

    return hosts


def scope_update(arr, scope_name):
    for item in arr:
        item['scope'] = scope_name


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt='%Y-%m-%d %H:%M',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(glob.tmp_dir + '/subs.log', 'w')
        ]
    )

    old_scopes_subs = []
    old_scopes_ports = []
    new_scopes_subs = []
    subs_now = []

    recon_domains = set()
    for scope in scopes:
        tmp_scope_subs = remove_duplicates(db['domains'].find({'scope': scope['name']}), 'host')
        for domain in scope['domains']:
            #same on dont recon?
            old_clean_subs = list(filter(lambda d: subdomain_isgood(d['host'], domain), tmp_scope_subs))
            extend_new_only(old_scopes_subs, old_clean_subs, 'host')
        #add cidrs/ips to old
        old_scopes_subs.extend(hosts_from_cidrs_ips(scope))
        # # add to old previously scaned ports ALWAYS TODO: filter date
        old_scopes_ports.extend(db['ports'].find({'scope': scope['name']}))
        if scope['subs_recon'] == True:
            recon_domains.update(scope['domains'])
        else:
            #process not recon inline
            logging.info(f"No recon scope {scope['name']} resolve all domains at once...")
            scope_subs_now = dnsx(scope['domains'])
            scope_update(scope_subs_now, scope['name'])
            extend_new_only(subs_now, scope_subs_now, 'host')
            logging.info(f"{scope['name']} {len(scope_subs_now)} resolved domains")

    #process recon domains
    logging.info(f"Recon flow on {len(recon_domains)} domains...")
    recon_domains = list(recon_domains)
    random.shuffle(recon_domains)
    allc = len(recon_domains)
    chunks_num = math.ceil(allc / config['puredns']['domains_in_chunk_max'])
    chunk_size = math.ceil(allc / chunks_num)     # medium chunk size

    chi = 1
    for i in range(0, allc, chunk_size):
        logging.info(f"Start recon chunk {chi}/{chunks_num} size {chunk_size}")
        chunk = recon_domains[i:i+chunk_size]
        recon_subs = domain_purespray(chunk, scopes, old_scopes_subs, 
                                   config['dnsgen']['max'],
                                   config['puredns']['rate'],
                                   config['puredns']['rate_trusted'],
                                   config['puredns']['timeout'],
                                   )
        chi += 1
        # weird counter for each parent domain on each chunk!
        logging.info(f"checking for subdomains weird results")
        recon_subs, _ = threshold_filter(recon_subs, "parent_host", config['sub_domains_weird_threshold'])
        #TODO: shuffledns on filtered
        # dnsx
        recon_subs = dnsx([x['host'] for x in recon_subs])
        # set scope
        domains_setscope(recon_subs, scopes)
        #log unknown domains !!! and remove it
        unknown_domains = list([ d for d in  recon_subs if d["scope"] == "unknown" ])
        if unknown_domains:
            logging.info(f"Unknown domains found !")
            for d in unknown_domains:
                logging.info(str(d))
                recon_subs.remove(d)
        #TODO: db inplace ?
        extend_new_only(subs_now, recon_subs, 'host')
        
    #remove new from old we are intersecting on changed subs !!!
    logging.info(f"db_get_modified on {len(subs_now)} domains")
    new_scopes_subs = db_get_modified_domains (subs_now, db['domains'])
    old_scopes_subs = list(filter( lambda o: o['host'] not in [n['host'] for n in new_scopes_subs], old_scopes_subs))    
    logging.info(f"{len(new_scopes_subs)} new/changed subdomains found!")

    # new and modified subdomains
    if len(new_scopes_subs) > 0:
        juicer(new_scopes_subs, domain_validators, scopes, config['juicer_filters'])
        domains_print_func = lambda x: f"{x['host']} {x.get('a_rev', '')} [{x['juicy_info']}]"
        notify_by_weight(new_scopes_subs, scopes, "domain(s)", domains_print_func, False, True)

        new_port_probes = []
        if args.ports:
            # otherports
            port_max = small_scopes_slice(new_scopes_subs, scopes, config['nuclei_one_time_max'])
            port_probes = portprobes(port_max, config['naabu']['ports_onnew'])
            port_probes, _ = threshold_filter(port_probes, "host", config['ports_weird_threshold'])
            new_port_probes = db_get_modified(port_probes, db['ports'], ['host','port'], ['host','ip','port','scope'], compare.port )
            #new ports only notify
            notify_ports(new_port_probes)
            # port checks
            new_ports_workflow(new_port_probes)
            new_scopes_subs.extend(port_probes) #all(old,new) ports on new/changed subdomain 

        sites_workflow(new_scopes_subs, config['httpx']['threads_onnew'])

    #ports on old subdomains
    new_port_probes = []
    if args.ports_olds:
        # otherports
        port_probes = portprobes(old_scopes_subs, config['naabu']['ports'])
        new_port_probes = db_get_modified(port_probes, db['ports'], ['host','port'], ['host','ip','port','scope'], compare.port )
        #new ports notify
        notify_ports(new_port_probes)
        # port checks
        new_ports_workflow(new_port_probes)
        #add new ports
        old_scopes_subs.extend(new_port_probes)

    #old subdomains
    if args.workflow_olds:
        #add old ports after args.ports_olds process!
        old_scopes_subs.extend(old_scopes_ports)

        logging.info("Проверяем старые домены (--workflow-olds)")
        sites_workflow(old_scopes_subs, config['httpx']['threads'])

    #it make sense only after worflow_olds (all new scanned activelly)
    if args.passive:
        logging.info("nuclei passive on all probes (it make sense only after worflow_olds) ")
        #project for collate scope on finded
        q = {"scope": {"$in": list([s["name"] for s in scopes])}}
        project = {"url": 1, "input": 1, "scope": 1}
        #http_probes include ports too
        passive_workflow( list(db['http_probes'].find(q, project)) )


def main_gc():
    '''
    Garbage collector:
    - del old httprobes
    '''
    httprobe_dirs = os.listdir('httprobes')
    httprobe_dirs.sort()
    while len(httprobe_dirs) > config['httprobes_history']:
        dir_todel = "httprobes/" + httprobe_dirs.pop(0)
        logging.info(f"Удаляем директорию с пробами {dir_todel}")
        shutil.rmtree(dir_todel, ignore_errors=True)

    #tmp dir
    tmp_dirs = os.listdir('tmp')
    tmp_dirs.sort()
    while len(tmp_dirs) > config['httprobes_history']:
        dir_todel = "tmp/" + tmp_dirs.pop(0)
        logging.info(f"Удаляем tmp директорию {dir_todel}")
        shutil.rmtree(dir_todel)


if __name__ == "__main__":
    args = cli_args()
    try:
        from config import config, scopes, db, glob, alerter
        os.makedirs(glob.httprobes_savedir, exist_ok=True)
        os.makedirs(glob.tmp_dir, exist_ok=True)
        main()
        main_gc()
    except Exception as x:
        traceback.print_exc()
        alerter.notify(f"Error at subs.py\n{str(x)}")
    finally:
        db.client.close()
