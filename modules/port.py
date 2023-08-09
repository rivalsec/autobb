import logging
import subprocess
from config import config
import json


def portprobes(domains, scan_ports):
    """naabu on domains search fo ports"""
    naabu_cmd = config["naabu"]['cmd'].copy()
    naabu_cmd.extend(['-p', scan_ports ])
    logging.info( f'{len(domains)} hosts | ' + ' '.join(naabu_cmd))
    naabu_res = subprocess.run(naabu_cmd, text=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, 
                                input="\n".join([x['host'] for x in domains]), errors="backslashreplace")
    if naabu_res.stderr:
        logging.error(naabu_res.stderr)
    ports = [json.loads(x) for x in naabu_res.stdout.splitlines()]
    # add scope from origin domains
    for port in ports:
        #ip portscan fix
        if 'host' not in port:
            port['host'] = port['ip']

        port_scope = next( (x['scope'] for x in domains if x['host'] == port['host']), None )
        if port_scope:
            port['scope'] = port_scope

    return ports