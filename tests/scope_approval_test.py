#!/usr/bin/env python3
"""Unit tests for human-approved apexes -> live scope (modules/scope_approval.py).

Run with: pytest tests/scope_approval_test.py
(scope_approval imports only logging — no MongoDB needed.)
"""
import logging

import pytest

from modules import scope_approval, scope_osint
from utils.common import domain_inscope


class FakeCol:
    """Records the query it was given and filters on `approval.status` the way Mongo would."""

    def __init__(self, docs):
        self.docs = docs
        self.queries = []

    def find(self, query=None, projection=None):
        self.queries.append(query)
        want = (query or {}).get('approval.status')
        out = []
        for d in self.docs:
            if want is not None and (d.get('approval') or {}).get('status') != want:
                continue
            out.append(d)
        return iter(out)


class FakeDB:
    def __init__(self, **cols):
        self.cols = {k: FakeCol(v) for k, v in cols.items()}

    def __getitem__(self, k):
        return self.cols.setdefault(k, FakeCol([]))


def _cand(apex, scope='s', status=None):
    doc = {'scope': scope, 'apex': apex}
    if status:
        doc['approval'] = {'status': status, 'by': 'telegram'}
    return doc


def _db(*docs):
    return FakeDB(scope_candidates=list(docs))


def _scope(name='s', domains=None, **extra):
    return {'name': name, 'domains': list(domains or []),
            'sub_refilters': [], 'subs_recon': True, **extra}


# ---------- approved_apexes ----------


def test_only_approved_are_returned():
    db = _db(_cand('yes.io', status='approved'),
             _cand('no.io', status='declined'),
             _cand('maybe.io'))
    assert scope_approval.approved_apexes(db) == {'s': ['yes.io']}


def test_grouped_per_scope_in_one_query():
    db = _db(_cand('a.io', 's1', 'approved'),
             _cand('b.io', 's1', 'approved'),
             _cand('c.io', 's2', 'approved'))
    assert scope_approval.approved_apexes(db) == {'s1': ['a.io', 'b.io'], 's2': ['c.io']}
    assert len(db['scope_candidates'].queries) == 1


def test_query_is_filtered_server_side():
    db = _db(_cand('a.io', status='approved'))
    scope_approval.approved_apexes(db)
    assert db['scope_candidates'].queries[0] == {'approval.status': 'approved'}


def test_nothing_approved_is_an_empty_map():
    assert scope_approval.approved_apexes(_db(_cand('x.io'))) == {}
    assert scope_approval.approved_apexes(_db()) == {}


@pytest.mark.parametrize('apex', ['  SIBLING.IO  ', 'sibling.io.', 'Sibling.IO'])
def test_apexes_are_normalised(apex):
    db = _db(_cand(apex, status='approved'))
    assert scope_approval.approved_apexes(db) == {'s': ['sibling.io']}


@pytest.mark.parametrize('doc', [
    {'scope': 's', 'apex': '', 'approval': {'status': 'approved'}},
    {'scope': 's', 'apex': None, 'approval': {'status': 'approved'}},
    {'scope': 's', 'approval': {'status': 'approved'}},
    {'apex': 'a.io', 'approval': {'status': 'approved'}},
    {'scope': '', 'apex': 'a.io', 'approval': {'status': 'approved'}},
    {'scope': 7, 'apex': 'a.io', 'approval': {'status': 'approved'}},
])
def test_malformed_docs_are_skipped(doc):
    assert scope_approval.approved_apexes(FakeDB(scope_candidates=[doc])) == {}


# ---------- apply_approved_apexes ----------


def test_approved_apex_joins_scope_domains():
    scopes = [_scope(domains=['foo.com'])]
    added = scope_approval.apply_approved_apexes(scopes, _db(_cand('sibling.io', status='approved')))
    assert scopes[0]['domains'] == ['foo.com', 'sibling.io']
    assert added == {'s': ['sibling.io']}


def test_declined_and_pending_never_join():
    scopes = [_scope(domains=['foo.com'])]
    scope_approval.apply_approved_apexes(
        scopes, _db(_cand('no.io', status='declined'), _cand('maybe.io')))
    assert scopes[0]['domains'] == ['foo.com']


def test_merge_is_idempotent_and_case_insensitive():
    scopes = [_scope(domains=['Sibling.IO'])]
    added = scope_approval.apply_approved_apexes(scopes, _db(_cand('sibling.io', status='approved')))
    assert scopes[0]['domains'] == ['Sibling.IO'], 'already configured -> no duplicate'
    assert added == {}


def test_each_scope_gets_only_its_own():
    scopes = [_scope('s1', ['a.com']), _scope('s2', ['b.com'])]
    scope_approval.apply_approved_apexes(
        scopes, _db(_cand('x.io', 's1', 'approved'), _cand('y.io', 's2', 'approved')))
    assert scopes[0]['domains'] == ['a.com', 'x.io']
    assert scopes[1]['domains'] == ['b.com', 'y.io']


def test_scope_with_no_configured_domains_becomes_scannable():
    scopes = [_scope(domains=[])]
    scope_approval.apply_approved_apexes(scopes, _db(_cand('sibling.io', status='approved')))
    assert scopes[0]['domains'] == ['sibling.io']


def test_approval_for_an_unconfigured_scope_is_warned_about(caplog):
    scopes = [_scope('s1', ['a.com'])]
    with caplog.at_level(logging.WARNING):
        added = scope_approval.apply_approved_apexes(
            scopes, _db(_cand('x.io', 'ghost-scope', 'approved')))
    assert added == {}
    assert scopes[0]['domains'] == ['a.com']
    assert 'ghost-scope' in caplog.text and 'unknown scope' in caplog.text


def test_merge_is_logged(caplog):
    scopes = [_scope(domains=['foo.com'])]
    with caplog.at_level(logging.INFO):
        scope_approval.apply_approved_apexes(scopes, _db(_cand('sibling.io', status='approved')))
    assert 'sibling.io' in caplog.text


def test_read_failure_is_loud_not_a_silently_narrower_scope():
    class Boom:
        def __getitem__(self, k):
            raise RuntimeError('mongo down')
    with pytest.raises(RuntimeError):
        scope_approval.apply_approved_apexes([_scope()], Boom())


# ---------- parity with a YAML-configured apex (the actual requirement) ----------


def test_approved_apex_is_in_scope_for_domain_inscope():
    """utils.common.domain_inscope gates every host AutoBB handles."""
    scope = _scope(domains=['foo.com'])
    assert domain_inscope('api.sibling.io', scope) is False
    scope_approval.apply_approved_apexes([scope], _db(_cand('sibling.io', status='approved')))
    assert domain_inscope('sibling.io', scope) is True
    assert domain_inscope('api.sibling.io', scope) is True
    assert domain_inscope('deep.a.b.sibling.io', scope) is True
    assert domain_inscope('notsibling.io', scope) is False
    assert domain_inscope('sibling.io.evil.com', scope) is False


def test_approved_apex_enters_subdomain_recon():
    """subs.py does `recon_domains.update(scope['domains'])` — the enumeration seed set."""
    scope = _scope(domains=['foo.com'])
    scope_approval.apply_approved_apexes([scope], _db(_cand('sibling.io', status='approved')))
    recon_domains = set()
    recon_domains.update(scope['domains'])
    assert recon_domains == {'foo.com', 'sibling.io'}


def test_approved_apex_stops_being_re_suggested():
    """scope_osint.scope_apexes is the exclusion set, so approval ends the suggestion loop."""
    scope = _scope(domains=['foo.com'])
    assert 'sibling.io' not in scope_osint.scope_apexes(scope)
    scope_approval.apply_approved_apexes([scope], _db(_cand('sibling.io', status='approved')))
    assert 'sibling.io' in scope_osint.scope_apexes(scope)


def test_a_declined_apex_stays_suggestable():
    scope = _scope(domains=['foo.com'])
    scope_approval.apply_approved_apexes([scope], _db(_cand('no.io', status='declined')))
    assert 'no.io' not in scope_osint.scope_apexes(scope)


def test_sub_refilters_still_apply_to_an_approved_apex():
    """An approved apex inherits the scope's own exclusions, exactly like a configured one."""
    scope = _scope(domains=['foo.com'], sub_refilters=[r'^internal\.'])
    scope_approval.apply_approved_apexes([scope], _db(_cand('sibling.io', status='approved')))
    assert domain_inscope('api.sibling.io', scope) is True
    assert domain_inscope('internal.sibling.io', scope) is False


def test_subs_recon_false_still_honoured_for_an_approved_apex():
    scope = _scope(domains=['foo.com'], subs_recon=False)
    scope_approval.apply_approved_apexes([scope], _db(_cand('sibling.io', status='approved')))
    assert domain_inscope('sibling.io', scope) is True        # the apex itself
    assert domain_inscope('api.sibling.io', scope) is False   # no subdomain walk
