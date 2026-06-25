"""Sibling apex-domain discovery from data already in MongoDB.

Mines an org's other registrable domains (apexes) it likely owns, using signals
AutoBB already stores — no crt.sh, no Shodan, no external calls:

    tls_san  -- http_probes.tls.subject_an / subject_cn (multi-domain certs)
    cname    -- out-of-scope domains.cname / http_probes.cnames targets
    ptr      -- out-of-scope domains.a_rev (reverse DNS)

A candidate is corroboration-gated: it must be seen via >= min_sources distinct
(type, evidence) signals, which keeps single weak hits out. Suggest-only — the
operator pastes confirmed apexes into scope.domains.

(v2 will add body-link + tracker-ID sources, which need the txt_harvester parser
refactored to yield out-of-scope hosts.)
"""
import re
import tldextract

_IP_RE = re.compile(r'\d{1,3}(?:\.\d{1,3}){3}')


def registrable_apex(host):
    """host -> registrable apex 'domain.suffix', or '' for IPs/invalid hosts.
    A leading '*.' is stripped first ('*.sibling.net' -> 'sibling.net'), since a
    wildcard cert SAN is strong evidence the org owns that apex."""
    if not host:
        return ''
    host = host.strip().lower().rstrip('.')
    if host.startswith('*.'):
        host = host[2:]
    if not host or _IP_RE.fullmatch(host):
        return ''
    ext = tldextract.extract(host)
    if not (ext.domain and ext.suffix):
        return ''
    return f"{ext.domain}.{ext.suffix}"


def scope_apexes(scope):
    """In-scope registrable apexes (to exclude from candidates)."""
    return {registrable_apex(d) for d in scope.get('domains', [])} - {''}


def mine(db, scope, cfg=None):
    """Return {apex: set((type, evidence))} of out-of-scope sibling apex
    candidates for one scope, from TLS SANs + CNAME + PTR already in Mongo."""
    cfg = cfg or {}
    name = scope['name']
    inscope = scope_apexes(scope)
    ignore = {a.strip().lower() for a in cfg.get('ignore_apexes', [])}
    cands = {}

    def consider(host, source):
        ap = registrable_apex(host)
        if not ap or ap in inscope or ap in ignore:
            return
        cands.setdefault(ap, set()).add(source)

    # TLS SANs: evidence keyed by the cert's subject_cn so one shared
    # multi-domain cert across many probes counts as a single source.
    for p in db['http_probes'].find({'scope': name, 'tls': {'$exists': True}}, {'tls': 1}):
        tls = p.get('tls') or {}
        cn = tls.get('subject_cn') or ''
        ev_key = cn.lstrip('*.').lower() or 'tls'
        names = list(tls.get('subject_an') or [])
        if cn:
            names.append(cn)
        for h in names:
            consider(h, ('tls_san', ev_key))

    # CNAME targets
    for d in db['domains'].find({'scope': name, 'cname': {'$exists': True}}, {'host': 1, 'cname': 1}):
        for cn in d.get('cname') or []:
            consider(cn, ('cname', (d.get('host') or '').lower()))
    for p in db['http_probes'].find({'scope': name, 'cnames': {'$exists': True}}, {'host': 1, 'cnames': 1}):
        for cn in p.get('cnames') or []:
            consider(cn, ('cname', (p.get('host') or '').lower()))

    # PTR (reverse DNS)
    for d in db['domains'].find({'scope': name, 'a_rev': {'$exists': True}}, {'host': 1, 'a_rev': 1}):
        for ptr in d.get('a_rev') or []:
            consider(ptr, ('ptr', (d.get('host') or '').lower()))

    return cands


_TYPE_ORDER = {'tls_san': 0, 'cname': 1, 'ptr': 2}


def summarize_sources(sources, max_examples=3):
    """Compact, readable evidence summary for an alert line, e.g.
    'tls_san×2, cname×5  (tinkoff.ru, certs.tinkoff.ru, cdn.tbank.ru +4)'.
    Groups by type with counts (strongest type first) and a few examples."""
    by_type = {}
    for t, e in sources:
        by_type.setdefault(t, []).append(e)
    types = sorted(by_type, key=lambda t: _TYPE_ORDER.get(t, 9))
    counts = ', '.join(f"{t}×{len(by_type[t])}" for t in types)
    examples = [e for t in types for e in by_type[t]]
    shown = ', '.join(examples[:max_examples])
    extra = len(examples) - max_examples
    if extra > 0:
        shown += f" +{extra}"
    return f"{counts}  ({shown})"


def candidates(db, scope, cfg=None):
    """Apex candidates meeting the corroboration threshold, as
    [(apex, sorted([(type, evidence), ...])), ...] sorted by source count desc."""
    cfg = cfg or {}
    min_sources = cfg.get('min_sources', 2)
    mined = mine(db, scope, cfg)
    out = [(ap, sorted(srcs)) for ap, srcs in mined.items() if len(srcs) >= min_sources]
    out.sort(key=lambda x: len(x[1]), reverse=True)
    return out
