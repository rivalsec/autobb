import logging
from typing import List
from subprocess import Popen, PIPE
import json
from config import config


def httprobes(domains:List[str], threads=20, savedir = False):
    '''
    savedir - if set, save http response to that directory
    domains - list of sub_domain Object (host) or port Object(host:port)
    '''
    httpx_cmd = config["httpx"]["cmd"].copy()
    httpx_cmd.extend(['-threads', str(threads)])
    if savedir:
        httpx_cmd.extend(['-sr', '-srd', savedir])

    logging.info(' '.join(httpx_cmd))

    proc = Popen(httpx_cmd, text=True, bufsize=1, stderr=PIPE, stdout=PIPE, stdin=PIPE, 
                        errors="backslashreplace")
    incount = 0
    with proc.stdin as stdin:
        for d in domains:
            host = f"{d['host']}:{d['port']}" if "port" in d else d['host']
            stdin.write(host + "\n")
            incount += 1
    logging.info(f"{incount} items writed to stdin")

    # add scope from origin domains
    for line in proc.stdout:
        logging.debug(line.strip())
        p = json.loads(line.strip())
        #validate cnames
        if 'cname' in p:
            p['cnames'] = p.pop('cname') #cnames is renamed to cname %)
            for cn in p['cnames']:
                if len(cn.split('.'))<2:
                    p['cnames'].remove(cn)
        # port obj
        if len(p['input'].split(':')) == 2:
            probe_host, _ = p['input'].split(':')
        else:
            probe_host = p['input']
        p['scope'] = next( (x['scope'] for x in domains if x['host'] == probe_host), "unknown" )
        logging.info(f"{p['scope']}: {p['url']} [{p['status_code']}] [{p.get('title','')}]")
        yield p
    
    with proc.stderr:
        for line in proc.stderr:
            print(line, end="")

