import logging
import json
import os
import re
import html
import tempfile
import hashlib
from subprocess import Popen, PIPE, TimeoutExpired
from urllib.parse import urlsplit
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import config, http_header_args
from modules.txt_harvester import _split_file


TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)


def _title_from_result(r: Dict, resultfile: str) -> str:
    """Pull the <title> out of an HTML ffuf match.

    With -od set, ffuf saves each match's raw request+response under that dir;
    `resultfile` is the resolved absolute path to it (ffuf's JSON reports only
    the basename, so the caller joins it onto the -od dir). We only bother for
    HTML matches (per the reported 'content-type'), read the response section,
    and return the collapsed, entity-decoded title. Returns '' when there is no
    saved file, the response isn't HTML, or no title is present."""
    if 'html' not in (r.get('content-type') or '').lower():
        return ''
    if not resultfile or not os.path.isfile(resultfile):
        return ''
    try:
        with open(resultfile, 'rb') as f:
            text = f.read().decode('utf-8', errors='replace')
    except OSError:
        return ''
    response, _ = _split_file(text)
    m = TITLE_RE.search(response)
    if not m:
        return ''
    return html.unescape(re.sub(r'\s+', ' ', m.group(1)).strip())[:200]


def _fuzz_one(probe: Dict, wordlist: str, threads: int, match_codes: str, timeout: int,
              savedir: str = None) -> List[Dict]:
    base_url = probe['url'].rstrip('/')
    target = f"{base_url}/FUZZ"

    # ffuf has no stdout JSON output -> always write to a tempfile
    fd, tmp_path = tempfile.mkstemp(suffix='.json', prefix='ffuf-')
    os.close(fd)

    cmd = config['httpfuzz']['cmd'].copy()
    cmd.extend([
        '-u', target,
        '-w', wordlist,
        '-mc', match_codes,
        '-t', str(threads),
        '-of', 'json',
        '-o', tmp_path,
    ])
    cmd.extend(http_header_args())
    probe_dir = None
    if savedir:
        # per-probe subdir so parallel ffuf workers don't collide
        slug = hashlib.md5(base_url.encode('utf-8', 'replace')).hexdigest()[:12]
        probe_dir = os.path.join(savedir, slug)
        os.makedirs(probe_dir, exist_ok=True)
        cmd.extend(['-od', probe_dir])
    logging.info(' '.join(cmd))

    try:
        proc = Popen(cmd, text=True, stdout=PIPE, stderr=PIPE, errors='backslashreplace')
        try:
            _, err = proc.communicate(timeout=timeout)
        except TimeoutExpired:
            proc.kill()
            proc.communicate()
            logging.warning(f"ffuf timeout on {target}")
            return []

        if proc.returncode != 0:
            logging.warning(f"ffuf exit {proc.returncode} on {target}: {(err or '').strip()[-300:]}")
            return []
        if not os.path.exists(tmp_path) or os.path.getsize(tmp_path) == 0:
            return []
        try:
            with open(tmp_path, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logging.warning(f"ffuf JSON parse failed on {target}: {e}")
            return []

        results = []
        for r in data.get('results', []):
            word = (r.get('input') or {}).get('FUZZ', '')
            full_url = r.get('url') or f"{base_url}/{word}"
            # ffuf reports resultfile as a basename relative to its -od dir
            resfile = r.get('resultfile') or ''
            abs_resfile = os.path.join(probe_dir, resfile) if (probe_dir and resfile) else ''
            hit = {
                'url': base_url,
                'full_url': full_url,
                'host': probe.get('host') or urlsplit(base_url).netloc,
                'scope': probe.get('scope', 'unknown'),
                'path': '/' + str(word).lstrip('/'),
                'status_code': r.get('status'),
                'content_length': r.get('length'),
                'words': r.get('words'),
                'lines': r.get('lines'),
                'redirect': r.get('redirectlocation', ''),
            }
            title = _title_from_result(r, abs_resfile)
            if title:
                hit['title'] = title
            # transient: absolute path to this match's saved response, used by
            # prune_fuzz_savedir to drop files for hits the filters discard.
            # Not in up_fields -> never persisted to db['http_paths'].
            if abs_resfile:
                hit['_resultfile'] = abs_resfile
            results.append(hit)
        return results
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def httpfuzz(probes, wordlist: str, threads: int = 40,
             match_codes: str = '200,204,301,302,307,401,403,405,500',
             timeout: int = 600, parallel: int = 4, savedir: str = None):
    '''
    Bruteforce dirs/files on each probe URL using ffuf — multiple ffuf
    processes in parallel across probes.

    probes - iterable of http probe dicts (must have 'url'; 'host'/'scope' used if present).
    threads - ffuf internal threads per process.
    parallel - number of ffuf processes to run concurrently across probes.
    savedir - if set, ffuf saves matched raw req/responses there (one subdir per probe).
    Yields one dict per match as workers complete.
    '''
    if not os.path.isfile(wordlist):
        logging.warning(f"httpfuzz wordlist not found: {wordlist}")
        return

    targets = [p for p in probes if p.get('url')]
    if not targets:
        return

    parallel = max(1, parallel)
    logging.info(f"httpfuzz: {len(targets)} target(s) x {parallel} parallel ffuf workers")
    if savedir:
        os.makedirs(savedir, exist_ok=True)

    with ThreadPoolExecutor(max_workers=parallel) as ex:
        futs = {ex.submit(_fuzz_one, p, wordlist, threads, match_codes, timeout, savedir): p
                for p in targets}
        for fut in as_completed(futs):
            probe = futs[fut]
            try:
                hits = fut.result()
            except Exception as e:
                logging.warning(f"httpfuzz error on {probe.get('url')}: {e}")
                continue
            for hit in hits:
                logging.info(f"{hit['scope']}: {hit}")
                yield hit


def prune_fuzz_savedir(savedir: str, keep_hits) -> int:
    """Delete saved ffuf response files that aren't referenced by keep_hits.

    ffuf writes one response file per match; the filter chain (prefix_cluster /
    scope_equal / threshold) drops the wildcard/soft-404 duplicates from the
    hit list but leaves their files on disk. Call this after a filter stage to
    bring the savedir down to the surviving set, so the downstream consumers
    (nuclei passive, gitleaks, harvester) only ever see deduplicated responses.

    keep_hits - surviving hit dicts; each kept hit's '_resultfile' is retained.
    Returns the number of files removed. Idempotent: re-running with a smaller
    keep set prunes further; a hit missing '_resultfile' (no savedir) is a no-op.
    """
    if not savedir or not os.path.isdir(savedir):
        return 0
    keep = {os.path.abspath(h['_resultfile']) for h in keep_hits if h.get('_resultfile')}
    removed = 0
    for root, _dirs, names in os.walk(savedir):
        for name in names:
            p = os.path.abspath(os.path.join(root, name))
            if p not in keep:
                try:
                    os.remove(p)
                    removed += 1
                except OSError as e:
                    logging.debug(f"[httpfuzz] prune remove failed {p}: {e}")
    # drop per-probe subdirs left empty by the prune
    for root, _dirs, _names in os.walk(savedir, topdown=False):
        if os.path.abspath(root) != os.path.abspath(savedir) and not os.listdir(root):
            try:
                os.rmdir(root)
            except OSError:
                pass
    logging.info(f"[httpfuzz] pruned {removed} non-surviving ffuf response(s) in {savedir}")
    return removed
