#!/usr/bin/env python3
"""Unit tests for CDN-front detection in asn.prefix change-noise suppression.

Run with: pytest compare_cdn_test.py
(compare.py has no config/Mongo import, so these run standalone.)
"""
import pytest

import compare

# a mixed-use cloud asn: cloudfront edges AND bare EC2 origins both live here, so
# it must never be listed in CDN_FRONT_ASNS — the CNAME is what tells them apart.
AWS = {'as_number': 16509, 'as_name': 'AMAZON-02', 'prefix': '13.33.204.0/22'}
AWS_OLD = {'as_number': 16509, 'as_name': 'AMAZON-02', 'prefix': '3.173.136.0/21'}


@pytest.fixture(autouse=True)
def _fronts():
    """Mirrors what subs.py loads from config['asn'] at startup."""
    compare.CDN_FRONT_ASNS = {34879, 204878}
    compare.CDN_FRONT_CNAMES = {'cloudfront.net', 'ghs.google.com', 'elb'}
    yield
    compare.CDN_FRONT_ASNS = set()
    compare.CDN_FRONT_CNAMES = set()


def _domain(new_cname, old_cname, new_asn=AWS, old_asn=AWS_OLD):
    return compare.domain(
        {'a': ['1.1.1.1'], 'cname': new_cname, 'asn': new_asn},
        {'a': ['2.2.2.2'], 'cname': old_cname, 'asn': old_asn, '_diffs_history': []},
    )['diffs']


# --- _cname_is_front matching semantics -------------------------------------

@pytest.mark.parametrize('host', [
    'd336o6rq4g8r2u.cloudfront.net',        # plain suffix
    'x.us-east-1.elb.amazonaws.com',        # aws emits both ELB orderings...
    'x.elb.us-west-2.amazonaws.com',        # ...so 'elb' must hit mid-chain too
    'ghs.google.com',                       # exact
])
def test_front_cnames_match(host):
    assert compare._cname_is_front(host)


@pytest.mark.parametrize('host', [
    'evilcloudfront.net',                   # partial label must NOT match
    'notcloudfront.net.attacker.com',       # lookalike must NOT match
    'ec2-1-2-3-4.compute-1.amazonaws.com',  # bare origin, not a front
    'my-bucket.s3.amazonaws.com',
    '',
    None,
])
def test_non_fronts_do_not_match(host):
    assert not compare._cname_is_front(host)


def test_chain_is_walked_not_just_first_hop():
    """~21% of fronted assets reach the edge via an in-scope alias first."""
    assert compare._has_front_cname({'cname': ['plus.example.com', 'd1.cloudfront.net']})
    assert compare._has_front_cname({'cnames': ['d1.cloudfront.net']})   # probes key
    assert not compare._has_front_cname({'a': ['1.2.3.4']})              # no cname


# --- suppression behaviour ---------------------------------------------------

def test_cdn_fronted_prefix_move_is_suppressed():
    assert _domain(['d1.cloudfront.net'], ['d1.cloudfront.net']) == {}


def test_bare_origin_prefix_move_still_alerts():
    """The whole point of not ASN-whitelisting AMAZON-02: a leaked EC2 origin
    must keep alerting even though its edges share the ASN."""
    assert 'asn.prefix' in _domain([], [])


def test_cname_change_still_alerts_on_fronted_host():
    """Suppression is scoped to asn.prefix only — a front swapped for an
    attacker-controlled target is exactly the signal to keep."""
    diffs = _domain(['evil.attacker.com'], ['d1.cloudfront.net'])
    assert 'cname.0' in diffs


def test_front_asn_still_suppresses_without_any_cname():
    ngenix = {'as_number': 34879, 'as_name': 'CCT-AS', 'prefix': '195.209.64.0/20'}
    ngenix_old = {'as_number': 34879, 'as_name': 'CCT-AS', 'prefix': '212.193.152.0/23'}
    assert _domain([], [], new_asn=ngenix, old_asn=ngenix_old) == {}


def test_status_and_title_changes_survive_on_fronted_probe():
    diffs = compare.http_probe(
        {'a': ['1.1.1.1'], 'cnames': ['d1.cloudfront.net'], 'asn': AWS,
         'status_code': 403, 'title': 'X'},
        {'a': ['2.2.2.2'], 'cnames': ['d1.cloudfront.net'], 'asn': AWS_OLD,
         'status_code': 200, 'title': 'X', '_diffs_history': []},
    )['diffs']
    assert diffs == {'status_code': 200}      # asn.prefix dropped, status kept
