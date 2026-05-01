"""Harvest in-scope hostnames + URLs from httpx-saved HTTP response files.

Walks a savedir (httpx -srd dir), parses each saved response, extracts
hostnames and absolute URLs from the response headers and body using the
same logic as the mitmproxy addon (mitm_subs.py), filters them through the
configured scopes, and writes two files into out_dir:

    subs.txt   -- bare in-scope hostnames
    links.txt  -- full in-scope absolute URLs (port preserved, query kept)

Saved-file format (httpx -srd):
    <request headers>
    <blank>
    <response headers>
    <blank>
    <response body>
    <blank>+
    <request URL>            (last non-empty line)
"""
import logging
import os
import re
from urllib.parse import urljoin, urlsplit, urlunsplit

from config import scopes
from modules.domain import subdomain_isgood


URL_RE = re.compile(r"""https?://[^\s"'<>`\\]+""", re.I)
REL_URL_RE = re.compile(r"""["'`](/[^"'`\s<>]{0,2000})["'`]""")
HOST_RE = re.compile(
    r'(?<![a-z0-9-])([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+){1,})(?![a-z0-9-])',
    re.I,
)
TRAIL_PUNCT = '.,;:)>]}\'"`'


def _strip_trail(s: str) -> str:
    while s and s[-1] in TRAIL_PUNCT:
        s = s[:-1]
    return s


def _is_ip(h: str) -> bool:
    return bool(re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', h))


def _norm_host(h: str) -> str:
    if not h:
        return ''
    h = h.strip().lower().rstrip('.')
    if ':' in h:
        h = h.split(':', 1)[0]
    if '*' in h:
        return ''
    return h


def _norm_url(raw: str, base: str = None) -> str:
    raw = _strip_trail(raw.strip())
    if not raw:
        return ''
    if base and not raw.lower().startswith(('http://', 'https://')):
        raw = urljoin(base, raw)
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return ''
    if parts.scheme not in ('http', 'https') or not host:
        return ''
    netloc = host.lower()
    if port is not None:
        netloc = f'{netloc}:{port}'
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or '', parts.query, ''))


def _host_in_scope(host: str) -> bool:
    if not host or _is_ip(host):
        return False
    check = host[2:] if host.startswith('*.') else host
    for s in scopes:
        if not s.get('subs_recon', True):
            continue
        for parent in s.get('domains', []):
            if subdomain_isgood(check, parent):
                if any(re.search(p, host) for p in s.get('sub_refilters', [])):
                    return False
                return True
    return False


def _split_file(text: str):
    """Return (response_section, base_url). Response section excludes request
    headers and the trailing URL line."""
    text = text.rstrip()
    if not text:
        return '', ''
    lines = text.splitlines()
    last = lines[-1].strip()
    if last.lower().startswith(('http://', 'https://')):
        base_url = last
        # drop the URL line + trailing blanks before it
        lines.pop()
        while lines and not lines[-1].strip():
            lines.pop()
    else:
        base_url = ''
    body = '\n'.join(lines)
    # split off the request portion at the first blank line
    parts = re.split(r'\r?\n\r?\n', body, maxsplit=1)
    response = parts[1] if len(parts) == 2 else body
    return response, base_url


def _record_host(host: str, seen: set):
    h = _norm_host(host)
    if not h or h in seen:
        return
    if not _host_in_scope(h):
        return
    seen.add(h)


def _record_url(raw: str, base: str, seen_urls: set, seen_hosts: set):
    url = _norm_url(raw, base or None)
    if not url or url in seen_urls:
        return
    host = urlsplit(url).hostname or ''
    if not _host_in_scope(host):
        return
    _record_host(host, seen_hosts)
    seen_urls.add(url)


def harvest_savedir(savedir: str, out_dir: str):
    if not os.path.isdir(savedir):
        logging.info(f"[txt-harvester] savedir not found: {savedir}; skip")
        return

    seen_hosts: set = set()
    seen_urls: set = set()
    files = 0

    for root, _dirs, names in os.walk(savedir):
        for name in names:
            if name == 'index.txt' or not name.endswith('.txt'):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, 'rb') as f:
                    text = f.read().decode('utf-8', errors='replace')
            except OSError as e:
                logging.debug(f"[txt-harvester] read fail {path}: {e}")
                continue
            response, base = _split_file(text)
            if not response:
                continue
            files += 1
            for m in URL_RE.finditer(response):
                _record_url(m.group(0), base, seen_urls, seen_hosts)
            for m in REL_URL_RE.finditer(response):
                _record_url(m.group(1), base, seen_urls, seen_hosts)
            for m in HOST_RE.finditer(response):
                _record_host(m.group(1), seen_hosts)

    os.makedirs(out_dir, exist_ok=True)
    subs_path = os.path.join(out_dir, 'subs.txt')
    links_path = os.path.join(out_dir, 'links.txt')
    with open(subs_path, 'w') as f:
        for h in sorted(seen_hosts):
            f.write(h + '\n')
    with open(links_path, 'w') as f:
        for u in sorted(seen_urls):
            f.write(u + '\n')
    logging.info(
        f"[txt-harvester] scanned {files} responses from {savedir} -> "
        f"{len(seen_hosts)} subs ({subs_path}), {len(seen_urls)} links ({links_path})"
    )
