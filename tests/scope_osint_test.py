#!/usr/bin/env python3
"""Unit tests for sibling apex discovery (modules/scope_osint.py).

Run with: pytest scope_osint_test.py
(scope_osint imports only tldextract — no MongoDB needed.)
"""
from modules import scope_osint


class FakeCol:
    def __init__(self, docs):
        self.docs = docs

    def find(self, query=None, projection=None):
        return iter(self.docs)


class FakeDB:
    def __init__(self, **cols):
        self.cols = {k: FakeCol(v) for k, v in cols.items()}

    def __getitem__(self, k):
        return self.cols.get(k, FakeCol([]))


SCOPE = {'name': 's', 'domains': ['foo.com']}


def test_registrable_apex():
    assert scope_osint.registrable_apex('a.b.sibling.net') == 'sibling.net'
    assert scope_osint.registrable_apex('*.sibling.net') == 'sibling.net'
    assert scope_osint.registrable_apex('foo.com') == 'foo.com'
    assert scope_osint.registrable_apex('1.2.3.4') == ''
    assert scope_osint.registrable_apex('') == ''


def _db():
    return FakeDB(
        http_probes=[
            {'scope': 's', 'tls': {'subject_cn': 'www.foo.com',
                                   'subject_an': ['api.foo.com',        # in-scope -> excluded
                                                  'a.sibling.net',      # candidate
                                                  'weak.org',           # 1 source only
                                                  'www.google.com']}},  # denylisted
        ],
        domains=[
            {'scope': 's', 'host': 'x.foo.com', 'cname': ['cdn.sibling.net']},
            {'scope': 's', 'host': 'y.foo.com', 'a_rev': ['host.sibling.net']},
        ],
    )


def test_candidates_corroboration_and_filters():
    cfg = {'min_sources': 2, 'ignore_apexes': ['google.com']}
    cands = dict(scope_osint.candidates(_db(), SCOPE, cfg))
    assert set(cands) == {'sibling.net'}                 # weak.org (1 src), google (deny), foo (in-scope) gone
    srcs = dict((t, e) for t, e in cands['sibling.net'])
    assert srcs == {'tls_san': 'www.foo.com', 'cname': 'x.foo.com', 'ptr': 'y.foo.com'}


def test_min_sources_one_includes_single_signal():
    cfg = {'min_sources': 1, 'ignore_apexes': ['google.com']}
    cands = dict(scope_osint.candidates(_db(), SCOPE, cfg))
    assert set(cands) == {'sibling.net', 'weak.org'}     # still no google.com / foo.com


def test_summarize_sources_compact():
    sources = [('cname', 'cdn.foo.com'), ('tls_san', 'tinkoff.ru'),
               ('tls_san', 'certs.tinkoff.ru'), ('cname', 'data.foo.com'),
               ('cname', 'fest.foo.com'), ('cname', 'a.foo.com')]
    out = scope_osint.summarize_sources(sources, max_examples=3)
    # strongest type first, counts, then 3 examples + overflow
    assert out.startswith("tls_san×2, cname×4  (")
    assert out.endswith(" +3)")

    one = scope_osint.summarize_sources([('tls_san', 'dolyame.ru')])
    assert one == "tls_san×1  (dolyame.ru)"


def test_probe_cname_evidence_keyed_by_hostname_not_ip():
    # http_probes.host is httpx's connected IP; the CNAME source must be keyed by
    # the probe hostname (input), so evidence is a hostname, not an IP, and two
    # hostnames sharing one IP stay distinct sources.
    db = FakeDB(http_probes=[
        {'scope': 's', 'input': 'a.foo.com', 'host': '1.2.3.4',
         'cnames': ['edge.sibling.net']},
        {'scope': 's', 'input': 'b.foo.com:443', 'host': '1.2.3.4',
         'cnames': ['edge.sibling.net']},
    ])
    cands = dict(scope_osint.candidates(db, SCOPE, {'min_sources': 2}))
    assert cands['sibling.net'] == [('cname', 'a.foo.com'), ('cname', 'b.foo.com')]


def test_shared_cert_counts_once_no_inflation():
    # same multi-domain cert seen on 3 probes -> tls_san is a single source,
    # so without other signals it stays below the >=2 threshold
    db = FakeDB(http_probes=[
        {'scope': 's', 'tls': {'subject_cn': 'www.foo.com', 'subject_an': ['x.sibling.net']}},
        {'scope': 's', 'tls': {'subject_cn': 'www.foo.com', 'subject_an': ['x.sibling.net']}},
        {'scope': 's', 'tls': {'subject_cn': 'www.foo.com', 'subject_an': ['x.sibling.net']}},
    ])
    assert scope_osint.candidates(db, SCOPE, {'min_sources': 2}) == []
    one = dict(scope_osint.candidates(db, SCOPE, {'min_sources': 1}))
    assert one['sibling.net'] == [('tls_san', 'www.foo.com')]
