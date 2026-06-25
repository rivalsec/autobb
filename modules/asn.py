"""Offline IP->ASN enrichment and ASN->prefix expansion.

Pure stdlib. Uses iptoasn.com's `ip2asn-combined.tsv` (public BGP-derived dump)
so both lookups we need are done in-process, with no API key and without leaking
the target list to a third party (unlike `asnmap` / httpx `-asn`, which proxy
target data through ProjectDiscovery).

TSV row format (tab-separated):
    range_start  range_end  AS_number  country_code  AS_description
`AS_number == 0` rows mark unannounced ranges and are skipped.

The dataset lives at a single path in the system temp dir. update_db() downloads
it there at pipeline start; load_db() reads it. Temp is always writable (no repo
clutter, non-root safe) and persists within a boot session so local runs reuse
it; in Docker it's ephemeral per container, so each run fetches a fresh copy.
Missing dataset -> enrichment degrades to a no-op.
"""
import bisect
import gzip
import ipaddress
import logging
import os
import shutil
import tempfile
import urllib.request

RUNTIME_TSV = os.path.join(tempfile.gettempdir(), 'autobb-ip2asn.tsv')

# {version: {'starts': [int,...], 'rows': [(start, end, asn, country, name),...]}}
# parallel lists kept sorted by start for bisect; cached for the process lifetime.
_DB = None


def load_db(path=None, force=False):
    """Parse the TSV once into per-version sorted tables. Cached on _DB."""
    global _DB
    if _DB is not None and not force:
        return _DB
    path = path or RUNTIME_TSV
    db = {4: {'starts': [], 'rows': []}, 6: {'starts': [], 'rows': []}, 'names': {}}
    rows = {4: [], 6: []}
    if not os.path.isfile(path):
        # No dataset (e.g. download failed/disabled): degrade to a no-op so
        # enrichment never breaks the pipeline.
        logging.warning(f"asn: dataset not found at {path}, ASN enrichment disabled")
        _DB = db
        return _DB
    names = {}
    with open(path, 'r', errors='replace') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            if len(parts) < 5:
                continue
            start_s, end_s, asn_s, country, name = parts[:5]
            try:
                asn = int(asn_s)
            except ValueError:
                continue
            if asn == 0:  # unannounced range
                continue
            try:
                start = ipaddress.ip_address(start_s)
                end = ipaddress.ip_address(end_s)
            except ValueError:
                continue
            rows[start.version].append((int(start), int(end), asn, country, name))
            names.setdefault(asn, name)   # number -> name, for resolving diffs
    for ver in (4, 6):
        rows[ver].sort()
        db[ver]['rows'] = rows[ver]
        db[ver]['starts'] = [r[0] for r in rows[ver]]
    db['names'] = names
    _DB = db
    logging.info(f"asn: loaded {len(rows[4])} v4 + {len(rows[6])} v6 ranges from {path}")
    return _DB


def lookup(ip):
    """IP string -> {as_number, as_name, country} or None. (Replaces httpx -asn.)"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    table = load_db()[addr.version]
    starts, rows = table['starts'], table['rows']
    i = bisect.bisect_right(starts, int(addr)) - 1
    if i < 0:
        return None
    start, end, asn, country, name = rows[i]
    if int(addr) > end:
        return None
    return {'as_number': asn, 'as_name': name, 'country': country}


def available():
    """True when a dataset is loaded with ranges. When False, callers should
    leave `asn` out of the stored fields so a missing dataset never unsets the
    field already on disk (a failed download must not delete prior ASN data)."""
    db = load_db()
    return bool(db[4]['rows'] or db[6]['rows'])


def name_for_asn(asn):
    """AS number -> name from the loaded dataset, or None. Used to make the
    number-only change diff readable in alerts."""
    try:
        asn = int(asn)
    except (TypeError, ValueError):
        return None
    return load_db().get('names', {}).get(asn)


def _as_str(num, name):
    if not num:
        return ''
    name = (name or '').strip()
    return f"AS{num}{' ' + name if name else ''}"


def tag(item):
    """Alert-line ASN context, with a leading space so it drops into existing
    format strings. Shows the current asn as ' [AS<num> <name>]', or the
    transition ' [AS<old> <oldname> -> AS<num> <name>]' when asn changed this
    run (the comparator diffs by number; we resolve names here for readability).
    '' when the item has no asn."""
    a = item.get('asn') or {}
    cur = _as_str(a.get('as_number'), a.get('as_name'))
    old_num = (item.get('diffs') or {}).get('asn.as_number')
    if old_num and old_num != 'null':
        old = _as_str(old_num, name_for_asn(old_num))
        return f" [{old} -> {cur or '?'}]"
    return f" [{cur}]" if cur else ''


def _set_asn(item, ip_field='a'):
    """Set item['asn'] from the first resolvable IP in item[ip_field]."""
    for ip in item.get(ip_field) or []:
        info = lookup(ip)
        if info:
            item['asn'] = info
            return


def enrich(items, ip_field='a'):
    """Tag each item in a list with its ASN, in place. No new requests:
    reuses A-records already collected by dnsx/httpx."""
    for item in items:
        _set_asn(item, ip_field)


def enrich_iter(items, ip_field='a'):
    """Streaming variant of enrich() for generator pipelines."""
    for item in items:
        _set_asn(item, ip_field)
        yield item


def prefixes_for_asn(asn):
    """ASN -> list of announced CIDR strings. (Replaces asnmap.)"""
    asn = int(asn)
    cidrs = []
    db = load_db()
    for ver in (4, 6):
        for start, end, row_asn, _country, _name in db[ver]['rows']:
            if row_asn != asn:
                continue
            net_start = ipaddress.ip_address(start)
            net_end = ipaddress.ip_address(end)
            cidrs += [str(c) for c in ipaddress.summarize_address_range(net_start, net_end)]
    return cidrs


def update_db(cfg):
    """Ensure the ip2asn dataset is available at pipeline start.

    Downloads it into the system temp dir when missing, or when `refresh`
    forces a fresh copy. Atomic + validated: a truncated/garbage download never
    replaces a working TSV, and any failure leaves the existing copy (if any) in
    place so the run continues (enrichment just no-ops when there's no dataset).
    """
    cfg = cfg or {}
    have = os.path.isfile(RUNTIME_TSV)
    if have and not cfg.get('refresh'):
        return
    url = cfg.get('url', 'https://iptoasn.com/data/ip2asn-combined.tsv.gz')
    timeout = cfg.get('timeout', 60)
    tmp = RUNTIME_TSV + '.tmp'
    try:
        os.makedirs(os.path.dirname(RUNTIME_TSV) or '.', exist_ok=True)
        req = urllib.request.Request(url, headers={'User-Agent': 'autobb-recon'})
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, 'wb') as out:
            stream = gzip.GzipFile(fileobj=resp) if url.endswith('.gz') else resp
            shutil.copyfileobj(stream, out)
        if not _valid_tsv(tmp):
            raise ValueError("downloaded TSV failed validation")
        os.replace(tmp, RUNTIME_TSV)  # atomic
        load_db(force=True)
        logging.info(f"asn: ip2asn dataset {'refreshed' if have else 'downloaded'}")
    except Exception as e:
        logging.warning(f"asn: download failed, ASN enrichment disabled ({e})")
        try:
            os.remove(tmp)
        except OSError:
            pass


def _valid_tsv(path, sample=20):
    """Non-empty and the first `sample` lines parse as ip2asn rows."""
    if os.path.getsize(path) == 0:
        return False
    seen = 0
    with open(path, 'r', errors='replace') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            if len(parts) < 5:
                return False
            try:
                ipaddress.ip_address(parts[0])
                ipaddress.ip_address(parts[1])
                int(parts[2])
            except ValueError:
                return False
            seen += 1
            if seen >= sample:
                break
    return seen > 0
