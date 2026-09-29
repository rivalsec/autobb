#!/usr/bin/env python3
"""Unit tests for offline IP->ASN enrichment (modules/asn.py).

Run with: pytest asn_test.py
(imports config -> needs a reachable MongoDB, same as the other repo tests.)
"""
import os

import compare
from modules import asn

# range_start  range_end  AS_number  country  AS_description
FIXTURE = (
    "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"
    "1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n"          # asn==0 -> skipped
    "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n"
    "2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE\n"
)


def _load_fixture(tmp_path):
    p = tmp_path / "ip2asn.tsv"
    p.write_text(FIXTURE)
    asn.load_db(path=str(p), force=True)
    return str(p)


def test_lookup_hits_and_boundaries(tmp_path):
    _load_fixture(tmp_path)
    assert asn.lookup("1.0.0.0")["as_number"] == 13335     # range start
    assert asn.lookup("1.0.0.0")["prefix"] == "1.0.0.0/24" # announced range
    assert asn.lookup("1.0.0.255")["as_number"] == 13335   # range end
    assert asn.lookup("8.8.8.8")["as_name"] == "GOOGLE"
    assert asn.lookup("2001:4860::8888")["as_number"] == 15169  # v6


def test_lookup_gaps_and_unannounced(tmp_path):
    _load_fixture(tmp_path)
    assert asn.lookup("1.0.1.50") is None   # asn==0 row was skipped
    assert asn.lookup("9.9.9.9") is None    # above all ranges
    assert asn.lookup("not-an-ip") is None


def test_prefixes_for_asn_falls_back_to_tsv(tmp_path, monkeypatch):
    _load_fixture(tmp_path)
    monkeypatch.setattr(asn, "load_pyasn", lambda *a, **k: None)   # no pyasn db
    assert asn.prefixes_for_asn(13335) == ["1.0.0.0/24"]
    assert asn.prefixes_for_asn(15169) == ["8.8.8.0/24", "2001:4860::/32"]
    assert asn.prefixes_for_asn(99999) == []


def test_prefixes_for_asn_prefers_pyasn(monkeypatch):
    class FakePyasn:
        def get_as_prefixes(self, num):
            return {"203.0.113.0/24", "198.51.100.0/24"} if num == 64500 else None

    monkeypatch.setattr(asn, "load_pyasn", lambda *a, **k: FakePyasn())
    assert asn.prefixes_for_asn(64500) == ["198.51.100.0/24", "203.0.113.0/24"]  # sorted
    assert asn.prefixes_for_asn(99999) == []   # None -> empty, no TSV fallback


def test_pyasn_build_runs_in_background_then_joins(monkeypatch):
    ran = []
    monkeypatch.setattr(asn, "_pyasn_thread", None)            # clean slate, restored on teardown
    monkeypatch.setattr(asn, "update_pyasn_db", lambda cfg: ran.append(cfg))
    asn.start_pyasn_db({"k": 1})
    asn.wait_pyasn_db()                                        # joins the thread
    assert ran == [{"k": 1}]


def test_update_pyasn_db_prebuilt_path_skips_build(tmp_path, monkeypatch):
    prebuilt = tmp_path / "prebuilt.dat"
    prebuilt.write_text("x")
    monkeypatch.setattr(asn, "PYASN_DAT", str(tmp_path / "auto.dat"))  # restored on teardown
    located = []
    monkeypatch.setattr(asn.shutil, "which", lambda n: located.append(n))
    asn.update_pyasn_db({"pyasn_db": str(prebuilt)})
    assert asn.PYASN_DAT == str(prebuilt)   # points at operator db
    assert not located                      # never looked for build tools


def test_enrich_uses_first_resolvable_ip(tmp_path):
    _load_fixture(tmp_path)
    items = [
        {'a': ['10.0.0.1', '8.8.8.8']},   # unresolvable first, public second
        {'a': ['9.9.9.9']},               # none resolve -> no asn key
        {},                                # no 'a' field at all
    ]
    asn.enrich(items)
    assert items[0]['asn']['as_number'] == 15169
    assert 'asn' not in items[1]
    assert 'asn' not in items[2]


def test_enrich_iter_streams(tmp_path):
    _load_fixture(tmp_path)
    out = list(asn.enrich_iter(iter([{'a': ['1.0.0.5']}])))
    assert out[0]['asn']['as_number'] == 13335


def test_missing_dataset_degrades_to_noop(tmp_path):
    asn.load_db(path=str(tmp_path / "does-not-exist.tsv"), force=True)
    assert asn.lookup("8.8.8.8") is None
    items = [{'a': ['8.8.8.8']}]
    asn.enrich(items)              # must not raise
    assert 'asn' not in items[0]


def test_tag_formats_asn_for_alert_lines():
    assert asn.tag({'asn': {'as_number': 13335, 'as_name': 'CLOUDFLARENET'}}) == " [AS13335 CLOUDFLARENET]"
    assert asn.tag({'asn': {'as_number': 13335}}) == " [AS13335]"   # no name
    assert asn.tag({'asn': {}}) == ""                                # no number
    assert asn.tag({}) == ""                                         # no asn key


def test_tag_shows_prefix_transition_on_change():
    item = {
        'asn': {'as_number': 15169, 'as_name': 'GOOGLE', 'prefix': '8.8.8.0/24'},
        'diffs': {'asn.prefix': '1.1.1.0/24'},              # network range moved
    }
    assert asn.tag(item) == " [1.1.1.0/24 -> AS15169 GOOGLE 8.8.8.0/24]"
    # null-origin transition is not rendered as a change
    assert asn.tag({'asn': {'as_number': 15169, 'as_name': 'GOOGLE', 'prefix': '8.8.8.0/24'},
                    'diffs': {'asn.prefix': 'null'}}) == " [AS15169 GOOGLE 8.8.8.0/24]"


def test_available_reflects_dataset(tmp_path):
    asn.load_db(path=str(tmp_path / "missing.tsv"), force=True)
    assert asn.available() is False
    _load_fixture(tmp_path)
    assert asn.available() is True


def test_asn_null_transitions_suppressed_only_prefix_to_prefix_alerts():
    AS1 = {'asn': {'prefix': '1.1.1.0/24'}}
    AS2 = {'asn': {'prefix': '8.8.8.0/24'}}
    # failed download / unresolved: prefix -> null must NOT alert
    assert compare.domain({}, AS1)['equal'] is True
    # first-time population: null -> prefix must NOT alert
    assert compare.domain(AS1, {})['equal'] is True
    # real network move: prefix -> prefix must alert
    assert compare.domain(AS2, AS1)['diffs'] == {'asn.prefix': '1.1.1.0/24'}
    # same on probes
    assert compare.http_probe({'status_code': 200}, dict(status_code=200, **AS1))['equal'] is True
    assert compare.http_probe(dict(status_code=200, **AS2),
                              dict(status_code=200, **AS1))['diffs'] == {'asn.prefix': '1.1.1.0/24'}


def test_asn_change_suppressed_when_ip_unchanged():
    A1 = {"as_number": 13335, "prefix": "1.1.1.0/24"}
    A2 = {"as_number": 15169, "prefix": "8.8.8.0/24"}
    ipx, ipy = ["1.1.1.1"], ["9.9.9.9"]
    # same IP set, asn reassigned by dataset churn -> silent (no alert)
    assert compare.domain({"a": ipx, "asn": A2}, {"a": ipx, "asn": A1})["equal"] is True
    assert compare.http_probe({"a": ipx, "status_code": 200, "asn": A2},
                              {"a": ipx, "status_code": 200, "asn": A1})["equal"] is True
    # reordered but same set -> still suppressed
    assert compare.domain({"a": ["1.1.1.1", "2.2.2.2"], "asn": A2},
                          {"a": ["2.2.2.2", "1.1.1.1"], "asn": A1})["equal"] is True
    # real IP move with prefix change -> alerts
    assert compare.domain({"a": ipy, "asn": A2}, {"a": ipx, "asn": A1})["diffs"] == {"asn.prefix": "1.1.1.0/24"}
    # asn churn on same IP but cname also changed -> only cname alerts, asn silent
    r = compare.domain({"a": ipx, "asn": A2, "cname": ["cdn.newhost.com"]},
                       {"a": ipx, "asn": A1, "cname": ["cdn.oldhost.com"]})
    assert r["diffs"] == {"cname.0": "cdn.oldhost.com"}
    # missing 'a' on either side -> cannot prove same IP -> not suppressed
    assert compare.domain({"asn": A2}, {"asn": A1})["diffs"] == {"asn.prefix": "1.1.1.0/24"}


def test_cdn_front_rotation_suppressed_but_cloud_origin_surfaces(monkeypatch):
    monkeypatch.setattr(compare, "CDN_FRONT_ASNS", set())   # rely on name pattern
    ipx, ipy = ["1.1.1.1"], ["9.9.9.9"]
    cdnA = {"as_number": 57363, "as_name": "CDNVIDEO-AS", "prefix": "185.1.0.0/24"}
    cdnB = {"as_number": 204720, "as_name": "CDNETWORKS", "prefix": "5.2.0.0/24"}
    cloudflare = {"as_number": 13335, "as_name": "CLOUDFLARENET", "prefix": "104.16.0.0/13"}
    aws = {"as_number": 16509, "as_name": "AMAZON-02", "prefix": "52.94.0.0/22"}     # cloud-hosted origin
    colo = {"as_number": 64500, "as_name": "EXAMPLE-COLO", "prefix": "203.0.113.0/24"}

    # CDN front -> CDN front (different providers) -> suppressed (new is a front)
    assert compare.domain({"a": ipy, "asn": cdnB}, {"a": ipx, "asn": cdnA})["equal"] is True
    # Cloudflare -> AWS origin -> ALERTS now: AWS is hosting, not a front (the split's point)
    assert compare.domain({"a": ipy, "asn": aws},
                          {"a": ipx, "asn": cloudflare})["diffs"] == {"asn.prefix": "104.16.0.0/13"}
    # Cloudflare -> colo origin -> ALERTS: real origin
    assert compare.domain({"a": ipy, "asn": colo},
                          {"a": ipx, "asn": cloudflare})["diffs"] == {"asn.prefix": "104.16.0.0/13"}


def test_org_asns_counts_filters_and_thresholds():
    docs = [
        {'asset': 'a1', 'asn': {'as_number': 64500, 'as_name': 'ORG'}},
        {'asset': 'a2', 'asn': {'as_number': 64500, 'as_name': 'ORG'}},
        {'asset': 'a3', 'asn': {'as_number': 64500, 'as_name': 'ORG'}},
        {'asset': 'a3', 'asn': {'as_number': 64500, 'as_name': 'ORG'}},   # dup asset
        {'asset': 'b1', 'asn': {'as_number': 13335, 'as_name': 'CLOUDFLARENET'}},
        {'asset': 'b2', 'asn': {'as_number': 13335, 'as_name': 'CLOUDFLARENET'}},
        {'asset': 'b3', 'asn': {'as_number': 13335, 'as_name': 'CLOUDFLARENET'}},
        {'asset': 'c1', 'asn': {'as_number': 64600, 'as_name': 'SMALL'}},  # below min
        {'asset': 'x1'},                                                   # no asn
    ]
    out = asn.org_asns(docs, cloud_asns=[13335], min_assets=3, host_field='asset')
    assert out == [(64500, 'ORG', 3)]   # dup not double-counted, cloud dropped, small below threshold


def test_org_asns_sorts_by_asset_count_desc():
    docs = [{'asset': f'a{i}', 'asn': {'as_number': 100, 'as_name': 'A'}} for i in range(2)]
    docs += [{'asset': f'b{i}', 'asn': {'as_number': 200, 'as_name': 'B'}} for i in range(5)]
    out = asn.org_asns(docs, cloud_asns=[], min_assets=2, host_field='asset')
    assert [num for num, _, _ in out] == [200, 100]


def test_update_db_present_and_disabled_is_noop(tmp_path, monkeypatch):
    runtime = tmp_path / "ip2asn.tsv"
    runtime.write_text(FIXTURE)               # dataset already present
    monkeypatch.setattr(asn, "RUNTIME_TSV", str(runtime))
    called = []
    monkeypatch.setattr(asn.urllib.request, "urlopen",
                        lambda *a, **k: called.append(1))
    asn.update_db({"refresh": False})
    asn.update_db(None)
    assert not called


def test_update_db_bootstraps_when_missing(tmp_path, monkeypatch):
    # no dataset present -> download even with refresh off
    monkeypatch.setattr(asn, "RUNTIME_TSV", str(tmp_path / "ip2asn.tsv"))
    called = []

    def fake_urlopen(req, timeout=None):
        called.append(1)
        raise RuntimeError("offline")        # bootstrap attempt, then fail-safe

    monkeypatch.setattr(asn.urllib.request, "urlopen", fake_urlopen)
    asn.update_db({"refresh": False})
    assert called


def test_update_db_bad_download_keeps_existing(tmp_path, monkeypatch):
    runtime = tmp_path / "ip2asn.tsv"
    runtime.write_text(FIXTURE)
    monkeypatch.setattr(asn, "RUNTIME_TSV", str(runtime))

    # fetch writes garbage to the .tmp file -> validation must reject it
    def fake_urlopen(req, timeout=None):
        raise RuntimeError("network down")
    monkeypatch.setattr(asn.urllib.request, "urlopen", fake_urlopen)

    asn.update_db({"refresh": True, "url": "http://x/ip2asn.tsv"})

    assert runtime.read_text() == FIXTURE            # untouched
    assert not os.path.exists(str(runtime) + ".tmp")  # tmp cleaned up
