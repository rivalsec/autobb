import logging
import subprocess
from config import config, glob, alerter
import json
import re
import os
from typing import Dict, List


def nuclei_active(nuclei_cmd_or: List[str], http_probes):
    # new site fingerpints nuclei scan
    nuclei_update() #? kostili?
    nuclei_cmd = nuclei_cmd_or.copy()
    for t in config['nuclei']['exclude_templates']:
        nuclei_cmd.extend(['-et', t])

    nuclei_stdin = "\n".join( [x['url'] for x in http_probes] )
    logging.info( f"{len(http_probes)} http_probes | " + " ".join(nuclei_cmd))
    nuclei_res = subprocess.run(nuclei_cmd, text=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, input=nuclei_stdin)
    logging.info(nuclei_res.stderr) #info here
    #check only on all templates scan
    if not '-tags' in nuclei_cmd:
        nuclei_check_templates_count(nuclei_res.stderr)
    logging.info(nuclei_res.stdout)
    nuclei_hits = [json.loads(x) for x in nuclei_res.stdout.splitlines()]
    for p in nuclei_hits:
        p_scope = next( (x['scope'] for x in http_probes if x['url'] == p['host']), None )
        # second attempt domain in url
        if not p_scope:
            p_scope = next( (x['scope'] for x in http_probes if p['host'] in x['url']), 'unknown' )
        p['scope'] = p_scope
    return nuclei_hits


def parse_passive_host(file: str):
    return file.split('/')[-2]


def nuclei_passive(probes_dir, all_probes, type = 'passive'):
    #delete (passive scanner can't parse it)
    index_file = glob.httprobes_savedir + '/index.txt'
    os.remove(index_file)

    if type == 'file':
        nuclei_cmd = config['nuclei']['file_cmd'].copy()
    else:
        nuclei_cmd = config['nuclei']['passive_cmd'].copy()

    nuclei_cmd.extend(['-target', probes_dir])
    for t in config['nuclei']['exclude_templates']:
        nuclei_cmd.extend(['-et', t])
    logging.info(" ".join(nuclei_cmd))
    nuclei_res = subprocess.run(nuclei_cmd, text=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    nuclei_check_templates_count(nuclei_res.stderr)
    logging.info(nuclei_res.stderr)
    logging.info(nuclei_res.stdout)
    nuclei_hits = [json.loads(x) for x in nuclei_res.stdout.splitlines()]

    for p in nuclei_hits:
        p['host'] = parse_passive_host(p['matched-at']) #only host[:port]
        p_scope = next( (x['scope'] for x in all_probes if '//' + p['host'] in x['url']) , 'unknown' )
        p['scope'] = p_scope
    return nuclei_hits


def nuclei_check_templates_count(nuclei_res_stderr):
    ''' парсим количество использованных шаблонов Templates loaded for scan: 507 '''
    templates_loaded = None
    templates_invalid = None
    m = re.search("Templates loaded for current scan: (\d+)", nuclei_res_stderr)
    if m:
        templates_loaded = int(m.group(1))
    m = re.search("Found (\d+) templates with syntax error", nuclei_res_stderr)
    if m:
        templates_invalid = int(m.group(1))
    
    if not templates_loaded or templates_loaded < 1000 or templates_invalid > 10:
        er_m = f"Something wrong with nuclei templates? loaded: {templates_loaded}, invalid: {templates_invalid}"
        alerter.notify(er_m)

    logging.info(f"nuclei templates check: loaded {templates_loaded}, invalid {templates_invalid}")
    return templates_loaded


def nuclei_update():
    logging.info("Обновляем шаблоны nuclei")
    nuclei_templates_dir = f"./nuclei-templates"
    # git clone templates to update https://github.com/projectdiscovery/nuclei-templates.git
    templ_up_res = subprocess.run(['nuclei', '-ut', '-ud', nuclei_templates_dir ], text=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
    logging.info(templ_up_res.stdout)