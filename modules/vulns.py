import logging
from subprocess import Popen, PIPE, run, STDOUT
from config import config, glob, alerter
import json
import re
import os
from typing import Dict, List
from utils.common import hit_tostr
from _thread import start_new_thread


nuclei_stderr = ""

def process_errors(stderr):
    global nuclei_stderr
    with stderr:
        for line in stderr:
            print(line, end="")
            nuclei_stderr += line


def nuclei_active(nuclei_cmd_or: List[str], http_probes):
    nuclei_update()
    nuclei_cmd = nuclei_cmd_or.copy()
    for t in config['nuclei']['exclude_templates']:
        nuclei_cmd.extend(['-et', t])

    logging.info(" ".join(nuclei_cmd))
    proc = Popen(nuclei_cmd, text=True, bufsize=1, stderr=PIPE, stdout=PIPE, stdin=PIPE, errors="backslashreplace")
    
    start_new_thread(process_errors, (proc.stderr,))
    start_new_thread(stdinwrite, (http_probes, proc.stdin))

    for line in proc.stdout:
        logging.debug(line.strip())
        p = json.loads(line.strip())
        p_scope = next( (x['scope'] for x in http_probes if x['url'] == p['host']), None )
        # second attempt domain in url
        if not p_scope:
            p_scope = next( (x['scope'] for x in http_probes if p['host'] in x['url']), 'unknown' )
        p['scope'] = p_scope
        logging.info(hit_tostr(p))
        yield p


    #check only on all templates scan
    if not '-tags' in nuclei_cmd:
        nuclei_check_templates_count(nuclei_stderr)


def stdinwrite(http_probes, stdin):
    incount = 0
    with stdin:
        for d in http_probes:
            stdin.write(d["url"] + "\n")
            incount += 1
    logging.info(f"{incount} items writed to stdin")


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
    nuclei_res = run(nuclei_cmd, text=True, stderr=PIPE, stdout=PIPE)
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
    ''' Templates loaded for scan: 507 '''
    templates_loaded = None
    templates_invalid = 0
    m = re.search("Templates loaded for current scan: (\d+)", nuclei_res_stderr)
    if m:
        templates_loaded = int(m.group(1))
    m = re.search("Found (\d+) templates with syntax error", nuclei_res_stderr)
    if m:
        templates_invalid = int(m.group(1))
    
    if not templates_loaded or templates_loaded < templates_invalid:
        er_m = f"Is something wrong with nuclei templates? loaded: {templates_loaded}, invalid: {templates_invalid}"
        alerter.notify(er_m)

    logging.info(f"nuclei templates check: loaded {templates_loaded}, invalid {templates_invalid}")
    return templates_loaded


def nuclei_update():
    logging.info("Updating nuclei tempates")
    nuclei_templates_dir = f"./nuclei-templates"
    # git clone templates to update https://github.com/projectdiscovery/nuclei-templates.git
    templ_up_res = run(['nuclei', '-ut', '-ud', nuclei_templates_dir ], text=True, stderr=STDOUT, stdout=PIPE)
    logging.info(templ_up_res.stdout)