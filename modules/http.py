import logging
from typing import Dict, List
import subprocess
import json
from config import config


def httprobes(domains:List[str], threads=20, savedir = False):
    '''
    savedir - if set, save http response to that directory
    domains - list of sub_domain Object (host) or port Object(host:port)
    '''
    domains_hosts = []
    non_probes = [] # items without http(s)
    for d in domains:
        if 'port' in d:
            domains_hosts.append(f"{d['host']}:{d['port']}")
            non_probes.append(d) # only with ports, cleanup later
        else:
            domains_hosts.append(d['host'])
    httpx_cmd = config["httpx"]["cmd"].copy()
    httpx_cmd.extend(['-threads', str(threads)])
    if savedir:
        httpx_cmd.extend(['-sr', '-srd', savedir])
    logging.info(' '.join(httpx_cmd))
    httpx_res = subprocess.run(httpx_cmd, text=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, 
                                input="\n".join(domains_hosts), errors="backslashreplace")
    if httpx_res.stderr:
        logging.error(httpx_res.stderr)
    probes = [json.loads(x) for x in httpx_res.stdout.splitlines()]
    # add scope from origin domains
    for p in probes:
        #validate cnames
        if 'cnames' in p:
            for cn in p['cnames']:
                if len(cn.split('.'))<2:
                    p['cnames'].remove(cn)
        # port obj
        if len(p['input'].split(':')) == 2:
            probe_host, probe_port = p['input'].split(':')
        else:
            probe_host = p['input']
            probe_port = None
        p_scope = next( (x['scope'] for x in domains if x['host'] == probe_host), None )
        if p_scope:
            p['scope'] = p_scope
        
        # clean up non http probes for network scans
        for host in non_probes:
            if host['host'] == probe_host and host['port'] == probe_port:
                non_probes.remove(host)
                continue
    
    #for nuclei
    for host in non_probes:
        host['url'] = f"{host['host']}:{host['port']}"

    return probes, non_probes

