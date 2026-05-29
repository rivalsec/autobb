import logging
import json
import os
import tempfile
import hashlib
from subprocess import Popen, PIPE, TimeoutExpired
from urllib.parse import urlsplit
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import config, http_header_args


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
            results.append({
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
            })
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
