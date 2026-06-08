"""Passive secret finder over saved httpx/ffuf HTTP responses via gitleaks.

Stages the *response section only* of each saved file (request headers stripped so
our own `http_headers.custom` tokens are never scanned), runs gitleaks over the
staging dir, and maps each finding back to its source URL/host.

gitleaks default rules are used (v1); a tuned ruleset can be wired later via
`config['secrets']['config']` ( -> `gitleaks -c <file>` ).
"""
import hashlib
import json
import logging
import os
import re
import tempfile
from subprocess import run, PIPE
from urllib.parse import urlsplit, urlunsplit

from config import config
from modules.txt_harvester import _split_file


def severity_for(rule_id: str) -> str:
    """Map a gitleaks rule_id to a severity via config['secrets']['severity'].

    Config shape: {default: <level>, <level>: [rule_id, ...], ...}. gitleaks has
    no native severity, so this is our own policy layer."""
    sev_cfg = config['secrets'].get('severity') or {}
    for level, rules in sev_cfg.items():
        if level == 'default':
            continue
        if rule_id in (rules or []):
            return level
    return sev_cfg.get('default', 'unknown')


def _compact(text: str) -> str:
    return re.sub(r'\s+', ' ', text or '').strip()


def _canonical_url(url: str) -> str:
    """Keep the response location stable across cache-buster/query changes."""
    parts = urlsplit(url or '')
    if not parts.scheme and not parts.netloc:
        return (url or '').split('?', 1)[0].split('#', 1)[0]
    return urlunsplit((
        parts.scheme.lower(),
        parts.netloc.lower(),
        parts.path or '/',
        '',
        '',
    ))


def fingerprint_secret_hit(rule_id: str, secret: str, match: str, url: str) -> dict:
    """Return a stable identity for alert dedupe.

    When gitleaks provides context around the secret, redact only the secret value
    and fingerprint the source location plus that redacted context. Rotating
    values like XSRF-TOKEN=<uuid> then update one finding. If the finding is only
    a bare value, fall back to the raw value hash so unrelated credentials are not
    collapsed blindly.
    """
    secret_sha256 = hashlib.sha256((secret or '').encode('utf-8', 'replace')).hexdigest()
    redacted_match = match or ''
    if secret:
        redacted_match = redacted_match.replace(secret, '<secret>')
    redacted_match = _compact(redacted_match)

    if redacted_match and redacted_match != '<secret>':
        basis = f"context\0{_canonical_url(url)}\0{redacted_match}"
        strategy = 'context'
    else:
        basis = f"value\0{secret_sha256}"
        strategy = 'value'

    return {
        'fingerprint': hashlib.sha256(f"{rule_id}\0{basis}".encode('utf-8', 'replace')).hexdigest(),
        'fingerprint_strategy': strategy,
        'match_redacted': redacted_match,
        'secret_sha256': secret_sha256,
    }


def _request_meta(text: str):
    """Parse the request block (lines before the first blank line) of a saved
    file. Returns (host, authority, path):
      host      - bare host, no port (scope/dedup)
      authority - Host header value, keeps any :port (URL building)
      path      - request-line target (e.g. /admin)
    Used for ffuf raw files, which have no trailing URL line for `_split_file`."""
    lines = text.splitlines()
    path = '/'
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].startswith('/'):
            path = parts[1]
    authority = ''
    for line in lines:
        s = line.strip()
        if not s:
            break
        if s.lower().startswith('host:'):
            authority = s.split(':', 1)[1].strip()
            break
    return authority.split(':', 1)[0].lower(), authority, path


def stage_bodies(savedirs, staging_dir: str, host_scheme: dict = None) -> dict:
    """Walk savedirs, write each response body into staging_dir, and return a
    map {staged_basename: {'path': src, 'url': base_url, 'host': host}}.

    host_scheme - optional {host: 'http'|'https'} from the httpx probes, used to
    pick the correct scheme when reconstructing ffuf URLs (the raw request has
    none). Falls back to https when a host isn't in the map."""
    if isinstance(savedirs, str):
        savedirs = [savedirs]
    host_scheme = host_scheme or {}
    os.makedirs(staging_dir, exist_ok=True)
    src_map: dict = {}

    for savedir in savedirs:
        if not os.path.isdir(savedir):
            logging.info(f"[secrets] savedir not found: {savedir}; skip")
            continue
        for root, _dirs, names in os.walk(savedir):
            for name in names:
                if name == 'index.txt':
                    continue
                path = os.path.join(root, name)
                try:
                    with open(path, 'rb') as f:
                        text = f.read().decode('utf-8', errors='replace')
                except OSError as e:
                    logging.debug(f"[secrets] read fail {path}: {e}")
                    continue
                response, base = _split_file(text)
                if not response.strip():
                    continue
                if base:                       # httpx: trailing URL line present
                    host = (urlsplit(base).hostname or '').lower()
                    url = base
                else:                          # ffuf: reconstruct from the request
                    host, authority, req_path = _request_meta(text)
                    # raw HTTP requests carry no scheme -> take it from the
                    # matching httpx probe, else assume https
                    scheme = host_scheme.get(host, 'https')
                    url = f"{scheme}://{authority}{req_path}" if authority else ''

                staged_name = hashlib.sha1(path.encode('utf-8', 'replace')).hexdigest() + '.txt'
                with open(os.path.join(staging_dir, staged_name), 'w') as f:
                    f.write(response)
                src_map[staged_name] = {'path': path, 'url': url, 'host': host}

    return src_map


def run_gitleaks(staging_dir: str) -> list:
    """Run gitleaks over staging_dir; return parsed JSON findings (list)."""
    cmd = config['secrets']['cmd'].copy()
    cfg = config['secrets'].get('config')
    if cfg:
        cmd.extend(['-c', cfg])

    fd, report = tempfile.mkstemp(suffix='.json', prefix='gitleaks-')
    os.close(fd)
    cmd.extend([staging_dir, '-r', report])
    logging.info(' '.join(cmd))

    try:
        res = run(cmd, text=True, stdout=PIPE, stderr=PIPE)
        # gitleaks exit codes: 0 = no leaks, 1 = leaks found, other = error
        if res.returncode not in (0, 1):
            logging.warning(f"[secrets] gitleaks exit {res.returncode}: {(res.stderr or '').strip()[-300:]}")
            return []
        try:
            with open(report) as f:
                return json.load(f) or []
        except (OSError, json.JSONDecodeError) as e:
            logging.warning(f"[secrets] gitleaks report parse failed: {e}")
            return []
    finally:
        try:
            os.remove(report)
        except OSError:
            pass


def secrets_scan(savedirs, staging_dir: str, host_scheme: dict = None) -> list:
    """Stage response bodies, run gitleaks, return hit dicts joined to source."""
    src_map = stage_bodies(savedirs, staging_dir, host_scheme)
    if not src_map:
        logging.info("[secrets] no response bodies staged; skip")
        return []

    hits = []
    for fnd in run_gitleaks(staging_dir):
        secret = fnd.get('Secret', '')
        src = src_map.get(os.path.basename(fnd.get('File', '')), {})
        rule_id = fnd.get('RuleID', '')
        match = fnd.get('Match', '')
        identity = fingerprint_secret_hit(rule_id, secret, match, src.get('url', ''))
        hits.append({
            'rule_id': rule_id,
            'severity': severity_for(rule_id),
            'description': fnd.get('Description', ''),
            'secret': secret,
            'secret_sha256': identity['secret_sha256'],
            'fingerprint': identity['fingerprint'],
            'fingerprint_strategy': identity['fingerprint_strategy'],
            'match_redacted': identity['match_redacted'],
            'match': match,
            'line': fnd.get('StartLine'),
            'file': src.get('path', fnd.get('File', '')),
            'url': src.get('url', ''),
            'host': src.get('host', ''),
        })
    logging.info(f"[secrets] gitleaks: {len(hits)} finding(s) from {len(src_map)} staged bodies")
    return hits
