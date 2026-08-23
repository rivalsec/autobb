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
import subprocess
import tempfile
import threading
import urllib.request

RUNTIME_TSV = os.path.join(tempfile.gettempdir(), 'autobb-ip2asn.tsv')
# pyasn .dat: ASN->prefix backend for discovery, built from a real BGP RIB (far
# more accurate than iptoasn for an org's core ASN). Optional/hybrid: iptoasn
# still does IP->ASN+name enrichment; prefixes_for_asn falls back to the TSV
# when no pyasn db is available.
PYASN_DAT = os.path.join(tempfile.gettempdir(), 'autobb-ipasn.dat')
_PYASN = None
_pyasn_thread = None

# {version: {'starts': [int,...], 'rows': [(start, end, asn, country, name),...]}}
# parallel lists kept sorted by start for bisect; cached for the process lifetime.
_DB = None


def load_db(path=None, force=False):
    """Parse the TSV once into per-version sorted tables. Cached on _DB."""
    global _DB
    if _DB is not None and not force:
        return _DB
    path = path or RUNTIME_TSV
    db = {4: {'starts': [], 'rows': []}, 6: {'starts': [], 'rows': []}}
    rows = {4: [], 6: []}
    if not os.path.isfile(path):
        # No dataset (e.g. download failed/disabled): degrade to a no-op so
        # enrichment never breaks the pipeline.
        logging.warning(f"asn: dataset not found at {path}, ASN enrichment disabled")
        _DB = db
        return _DB
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
    for ver in (4, 6):
        rows[ver].sort()
        db[ver]['rows'] = rows[ver]
        db[ver]['starts'] = [r[0] for r in rows[ver]]
    _DB = db
    logging.info(f"asn: loaded {len(rows[4])} v4 + {len(rows[6])} v6 ranges from {path}")
    return _DB


def _range_to_prefix(start, end):
    """iptoasn range [start_int, end_int] -> a stable CIDR string identifying the
    announced network block (comma-joined when the range spans several CIDRs)."""
    nets = ipaddress.summarize_address_range(
        ipaddress.ip_address(start), ipaddress.ip_address(end))
    return ','.join(str(n) for n in nets)


def lookup(ip):
    """IP string -> {as_number, as_name, country, prefix} or None.
    `prefix` is the announced network range the IP falls in (the stable unit for
    change detection). (Replaces httpx -asn.)"""
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
    return {'as_number': asn, 'as_name': name, 'country': country,
            'prefix': _range_to_prefix(start, end)}


def available():
    """True when a dataset is loaded with ranges. When False, callers should
    leave `asn` out of the stored fields so a missing dataset never unsets the
    field already on disk (a failed download must not delete prior ASN data)."""
    db = load_db()
    return bool(db[4]['rows'] or db[6]['rows'])


def _as_str(num, name):
    if not num:
        return ''
    name = (name or '').strip()
    return f"AS{num}{' ' + name if name else ''}"


def tag(item):
    """Alert-line ASN context, with a leading space so it drops into existing
    format strings. Shows the current asn as ' [AS<num> <name> <prefix>]', or the
    transition ' [<old_prefix> -> AS<num> <name> <prefix>]' when the network range
    changed this run (the comparator diffs by prefix). '' when no asn."""
    a = item.get('asn') or {}
    cur = _as_str(a.get('as_number'), a.get('as_name'))
    prefix = a.get('prefix')
    if cur and prefix:
        cur = f"{cur} {prefix}"
    old_prefix = (item.get('diffs') or {}).get('asn.prefix')
    if old_prefix and old_prefix != 'null':
        return f" [{old_prefix} -> {cur or '?'}]"
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


def load_pyasn(path=None, force=False):
    """Return a loaded pyasn object (BGP RIB-based ASN<->prefix db), or None when
    pyasn isn't installed or the .dat is missing. Cached for the process."""
    global _PYASN
    if _PYASN is not None and not force:
        return _PYASN or None
    path = path or PYASN_DAT
    if not os.path.isfile(path):
        return None
    try:
        import pyasn
        _PYASN = pyasn.pyasn(path)
        logging.info(f"asn: pyasn prefix db loaded from {path}")
    except Exception as e:
        logging.warning(f"asn: pyasn db unavailable ({e})")
        _PYASN = False   # sentinel: tried and failed, don't retry
    return _PYASN or None


def update_pyasn_db(cfg):
    """Build the pyasn .dat from the latest RouteViews RIB, for the discovery
    prefix source. Heavy (~70MB RIB download + convert), so only called when
    suggestion runs. Uses a prebuilt db at cfg['pyasn_db'] when set; otherwise
    auto-builds into temp when missing (or cfg['pyasn_refresh']). Atomic +
    fail-safe: any failure leaves prefixes_for_asn to fall back to iptoasn."""
    cfg = cfg or {}
    global PYASN_DAT
    prebuilt = cfg.get('pyasn_db')
    if prebuilt:
        PYASN_DAT = prebuilt
        return                       # operator-managed db, never auto-build
    if os.path.isfile(PYASN_DAT) and not cfg.get('pyasn_refresh'):
        return
    dl = shutil.which('pyasn_util_download.py')
    conv = shutil.which('pyasn_util_convert.py')
    if not (dl and conv):
        logging.warning("asn: pyasn utils not found, discovery falls back to iptoasn prefixes")
        return
    timeout = cfg.get('pyasn_build_timeout', 600)
    with tempfile.TemporaryDirectory() as td:
        rib = os.path.join(td, 'rib.bz2')
        tmp = PYASN_DAT + '.tmp'
        try:
            subprocess.run([dl, '--latestv46', '--filename', rib],
                           check=True, capture_output=True, timeout=timeout)
            subprocess.run([conv, '--single', rib, tmp],
                           check=True, capture_output=True, timeout=timeout)
            os.replace(tmp, PYASN_DAT)
            load_pyasn(force=True)
            logging.info("asn: pyasn prefix db built from latest RIB")
        except Exception as e:
            logging.warning(f"asn: pyasn db build failed, using iptoasn prefixes ({e})")
            try:
                os.remove(tmp)
            except OSError:
                pass


def start_pyasn_db(cfg):
    """Kick off the pyasn db build in a background thread so the heavy RIB
    download + convert overlaps the recon pipeline instead of blocking at
    suggest-time. Idempotent. Call wait_pyasn_db() before prefixes_for_asn()."""
    global _pyasn_thread
    if _pyasn_thread is not None:
        return
    _pyasn_thread = threading.Thread(target=update_pyasn_db, args=(cfg,),
                                     name='pyasn-build', daemon=True)
    _pyasn_thread.start()
    logging.info("asn: pyasn db build started in background")


def wait_pyasn_db(timeout=None):
    """Block until the background pyasn build (if any) finishes. If it's still
    running after `timeout`, prefixes_for_asn just falls back to iptoasn until
    the db lands (the atomic write means a half-built db is never read)."""
    if _pyasn_thread is not None:
        _pyasn_thread.join(timeout)
        if _pyasn_thread.is_alive():
            logging.warning("asn: pyasn db build still running, using iptoasn prefixes for now")


def prefixes_for_asn(asn):
    """ASN -> list of announced CIDR strings. Prefers the pyasn RIB db (accurate
    for org core ASNs); falls back to the iptoasn TSV when pyasn is unavailable.
    (Replaces asnmap.)"""
    asn = int(asn)
    pa = load_pyasn()
    if pa is not None:
        return sorted(pa.get_as_prefixes(asn) or [])
    return _prefixes_from_tsv(asn)


def _prefixes_from_tsv(asn):
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


def org_asns(docs, cloud_asns=(), min_assets=3, host_field='host'):
    """Find likely org-owned ASNs from confirmed assets.

    Counts distinct assets (by host_field) per asn.as_number across docs, drops
    ASNs in the cloud/CDN denylist, and keeps those with >= min_assets. Returns
    [(as_number, as_name, asset_count), ...] sorted by count desc.
    """
    cloud = {int(a) for a in cloud_asns}
    seen = {}   # as_number -> {'name', 'hosts': set()}
    for d in docs:
        a = d.get('asn') or {}
        num = a.get('as_number')
        if not num or int(num) in cloud:
            continue
        num = int(num)
        host = d.get(host_field)
        if not host:
            continue
        entry = seen.setdefault(num, {'name': a.get('as_name') or '', 'hosts': set()})
        entry['hosts'].add(host)
    out = [(num, e['name'], len(e['hosts']))
           for num, e in seen.items() if len(e['hosts']) >= min_assets]
    out.sort(key=lambda x: x[2], reverse=True)
    return out


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
