import logging
from subprocess import Popen, PIPE, run, STDOUT, TimeoutExpired
from config import config, alerter, http_header_args
import json
import re
import os
import hashlib
from threading import Timer
from typing import Dict, List
from utils.common import hit_tostr
from modules.secrets import _request_meta
from _thread import start_new_thread


nuclei_stderr = ""

def process_errors(stderr):
    global nuclei_stderr
    nuclei_stderr = "" # clean up on start 
    with stderr:
        for line in stderr:
            logging.info(line.strip())
            nuclei_stderr += line


def nuclei_active(nuclei_cmd_or: List[str], http_probes):
    nuclei_update()
    nuclei_cmd = nuclei_cmd_or.copy()
    nuclei_cmd.extend(http_header_args())
    for t in config['nuclei']['exclude_templates']:
        nuclei_cmd.extend(['-et', t])

    logging.info(" ".join(nuclei_cmd))
    proc = Popen(nuclei_cmd, text=True, bufsize=1, stderr=PIPE, stdout=PIPE, stdin=PIPE, errors="backslashreplace")

    timeout = config['nuclei'].get('scan_timeout') or 0
    timer = None
    if timeout:
        def _kill_on_timeout():
            logging.warning(f"nuclei scan exceeded {timeout}s, terminating")
            proc.terminate()
        timer = Timer(timeout, _kill_on_timeout)
        timer.start()

    start_new_thread(process_errors, (proc.stderr,))
    start_new_thread(stdinwrite, (http_probes, proc.stdin))

    try:
        for line in proc.stdout:
            logging.debug(line.strip())
            try:
                p = json.loads(line.strip())
            except:
                continue
            if 'matched-at' not in p:
                p['matched-at'] = p['url']
            p_scope = next( (x['scope'] for x in http_probes if x['url'] == p['host']), None )
            # second attempt domain in url
            if not p_scope:
                p_scope = next( (x['scope'] for x in http_probes if p['host'] in x['url']), 'unknown' )
            p['scope'] = p_scope
            logging.info(hit_tostr(p))
            yield p
    finally:
        if timer:
            timer.cancel()

    #check only on all templates scan
    if not '-tags' in nuclei_cmd:
        nuclei_check_templates_count(nuclei_stderr, nuclei_cmd)


def stdinwrite(http_probes, stdin):
    incount = 0
    with stdin:
        for d in http_probes:
            stdin.write(d["url"] + "\n")
            incount += 1
    logging.info(f"{incount} items writed to stdin")


def parse_passive_host(file: str):
    return file.split('/')[-2]


def _parse_hit_line(line, where):
    """Parse one JSONL stdout line into a hit dict, or None to skip it. Tolerates
    the junk nuclei/panuclei sometimes emit (blank lines, non-JSON noise, and
    bare chunk markers like "0" that parse as valid JSON but aren't hit objects)
    so one bad line can't abort the whole passive pass."""
    if not line.strip():
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        logging.warning(f"{where}: skipping non-JSON stdout line: {line[:200]!r}")
        return None
    if not isinstance(obj, dict):
        logging.warning(f"{where}: skipping non-object stdout line: {line[:200]!r}")
        return None
    return obj


def nuclei_passive(probes_dir, all_probes, type = 'passive'):
    # httpx/ffuf drop an index.txt the passive scanner can't parse (one
    # "malformed raw http response" error per template pass). Remove any under
    # the dir we're actually about to scan -- httpx writes it to
    # <savedir>/response/index.txt, not the root, so the old fixed root path
    # missed it and flooded the log.
    for root, _dirs, names in os.walk(probes_dir):
        if 'index.txt' in names:
            try:
                os.remove(os.path.join(root, 'index.txt'))
            except OSError:
                pass

    if type == 'file':
        nuclei_cmd = config['nuclei']['file_cmd'].copy()
    else:
        nuclei_cmd = config['nuclei']['passive_cmd'].copy()

    nuclei_cmd.extend(['-target', probes_dir])
    nuclei_cmd.extend(http_header_args())
    for t in config['nuclei']['exclude_templates']:
        nuclei_cmd.extend(['-et', t])
    logging.info(" ".join(nuclei_cmd))
    nuclei_res = run(nuclei_cmd, text=True, stderr=PIPE, stdout=PIPE)
    nuclei_check_templates_count(nuclei_res.stderr, nuclei_cmd)
    logging.info(nuclei_res.stderr)
    logging.info(nuclei_res.stdout)
    # nuclei occasionally emits junk on stdout (e.g. raw response
    # chunked-transfer/HTML bleeding into the stream); a single bad line must not
    # take down the whole pass, so skip it like nuclei_active does. Note a bare
    # chunk marker like "0" is valid JSON but not a hit object, so also drop any
    # parsed value that isn't a dict -- otherwise it crashes the loop below.
    nuclei_hits = [h for h in (_parse_hit_line(x, 'nuclei_passive')
                               for x in nuclei_res.stdout.splitlines()) if h is not None]

    for p in nuclei_hits:
        p['host'] = parse_passive_host(p['matched-at']) #only host[:port]
        p_scope = next( (x['scope'] for x in all_probes if '//' + p['host'] in x['url']) , 'unknown' )
        p['scope'] = p_scope
    return nuclei_hits


def _trailing_url(file, _cache={}):
    """Last line of a saved httpx/ffuf response file is the probe URL. panuclei
    reports the file path as matched-at, so recover the URL for nicer alerts
    (cache keyed by path; per-run timestamped dirs keep paths unique)."""
    if file in _cache:
        return _cache[file]
    url = None
    try:
        with open(file, 'rb') as f:
            lines = f.read().decode('utf-8', 'ignore').rstrip().splitlines()
        if lines and lines[-1].strip().startswith(('http://', 'https://')):
            url = lines[-1].strip()
    except OSError:
        pass
    _cache[file] = url
    return url


def panuclei_passive(probes_dir, all_probes):
    """Passive scan via panuclei (github.com/rivalsec/panuclei). It reads httpx
    -srd files directly and evaluates word/regex/status/DSL matchers. Returns
    hits in the same shape as nuclei_passive so the caller's dedup/notify path
    is unchanged. exclude_templates (path prefixes) are forwarded as -et."""
    pan_cmd = config['nuclei']['panuclei_cmd'].copy()
    pan_cmd.extend(['-u', probes_dir])
    for t in config['nuclei'].get('exclude_templates', []):
        pan_cmd.extend(['-et', t])
    logging.info(" ".join(pan_cmd))
    res = run(pan_cmd, text=True, stderr=PIPE, stdout=PIPE)
    logging.info(res.stderr)
    hits = [h for h in (_parse_hit_line(x, 'panuclei_passive')
                        for x in res.stdout.splitlines()) if h is not None]
    for p in hits:
        p['host'] = parse_passive_host(p['matched-at'])
        p['scope'] = next((x['scope'] for x in all_probes if '//' + p['host'] in x['url']), 'unknown')
        url = _trailing_url(p['matched-at'])
        if url:
            p['url'] = url
    return hits


def run_passive(probes_dir, all_probes):
    """Dispatch the passive scan to the configured engine (nuclei | panuclei)."""
    engine = (config['nuclei'].get('passive_engine') or 'nuclei').lower()
    if engine == 'panuclei':
        return panuclei_passive(probes_dir, all_probes)
    return nuclei_passive(probes_dir, all_probes)


# ffuf -od stores a match as "<raw request>\n---- ^ Request .. Response v ----\n<raw response>";
# nuclei's passive reader (and parse_passive_host) expect httpx -srd's
# "<request>\n\n<response>\n\n<url>" under a <host>/ dir. These split the two apart.
_FFUF_SEP_RE = re.compile(r'(?m)^-+.*Request.*Response.*-+\s*$')
_HTTP_STATUS_RE = re.compile(r'(?m)^HTTP/\d')


def stage_fuzz_for_passive(savedir: str, stage_dir: str, host_scheme: dict = None):
    """Restage ffuf response files into httpx -srd format under a <host>/ tree
    so nuclei_passive parses them and maps host->scope (via parse_passive_host)
    exactly like httpx responses.

    host_scheme - optional {host: 'http'|'https'} to rebuild the url line (the
    raw request carries no scheme); defaults to https. Returns stage_dir when at
    least one file was staged, else None."""
    if not savedir or not os.path.isdir(savedir):
        return None
    host_scheme = host_scheme or {}
    staged = 0
    for root, _dirs, names in os.walk(savedir):
        for name in names:
            if name == 'index.txt':
                continue
            src = os.path.join(root, name)
            try:
                with open(src, 'rb') as f:
                    text = f.read().decode('utf-8', errors='replace')
            except OSError:
                continue
            sm = _HTTP_STATUS_RE.search(text)
            if not sm:
                continue                       # no parseable HTTP response
            response = text[sm.start():]
            sep = _FFUF_SEP_RE.search(text, 0, sm.start())
            request = text[:sep.start()] if sep else text[:sm.start()]
            host, authority, path = _request_meta(text)
            if not host:
                continue
            scheme = host_scheme.get(host, 'https')
            url = f"{scheme}://{authority}{path}" if authority else ''
            host_dir = os.path.join(stage_dir, host)
            os.makedirs(host_dir, exist_ok=True)
            dst = os.path.join(host_dir, hashlib.sha1(src.encode('utf-8', 'replace')).hexdigest() + '.txt')
            # frame byte-identically to httpx -srd: CRLF line endings and a CRLF
            # blank line between request/response/url. The request's own trailing
            # CRLFs must survive (an LF-only '\n\n' here leaves nuclei unable to
            # terminate the request headers, so it never isolates the response body).
            out = request.rstrip() + "\r\n\r\n" + response.rstrip() + "\r\n\r\n" + url + "\r\n"
            with open(dst, 'w', newline='') as f:
                f.write(out)
            staged += 1
    logging.info(f"[passive] staged {staged} ffuf response(s) from {savedir} -> {stage_dir}")
    return stage_dir if staged else None


def nuclei_check_templates_count(nuclei_res_stderr, nuclei_cmd=None):
    ''' Templates loaded for scan: 507 '''
    # -silent suppresses the "Templates loaded for current scan" stats line,
    # so the count can't be parsed — skip the check to avoid a false alert.
    if nuclei_cmd and '-silent' in nuclei_cmd:
        logging.info("nuclei templates check skipped (-silent)")
        return None
    templates_loaded = None
    templates_invalid = 0
    m = re.search(r"Templates loaded for current scan: (\d+)", nuclei_res_stderr)
    if m:
        templates_loaded = int(m.group(1))
    m = re.search(r"Found (\d+) templates with syntax error", nuclei_res_stderr)
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