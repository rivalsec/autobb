"""Idempotent MongoDB index setup. Call ensure_indexes(db) once at startup.

Each entry: (keys, options). keys is a list of (field, direction) tuples.

The (scope, triage.status) indexes below are `sparse` on purpose: most
findings have no `triage` field at all (implicitly "new" — see
modules/triage.py), so a sparse index keeps only the minority that's actually
been triaged, which is exactly what a "show me confirmed/false_positive
findings" query (e.g. from a future UI) filters on. A query for the untriaged
majority doesn't need this index.
"""

from .triage import TRIAGE_FIELD

_TRIAGE_STATUS_INDEX = ([('scope', 1), (f'{TRIAGE_FIELD}.status', 1)], {'sparse': True})

INDEXES = {
    'domains': [
        ([('host', 1)], {}),
        ([('scope', 1), ('last_alive', 1)], {}),
    ],
    'http_probes': [
        ([('url', 1)], {}),
        ([('scope', 1), ('last_alive', 1)], {}),
        ([('last_alive', 1)], {}),
        ([('last_nuclei_scan', 1)], {}),
        ([('last_httpfuzz_scan', 1)], {}),
        ([('scope', 1), ('asn.as_number', 1)], {}),
    ],
    'http_paths': [
        ([('url', 1), ('path', 1)], {}),
        ([('scope', 1), ('last_alive', 1)], {}),
        _TRIAGE_STATUS_INDEX,
    ],
    'ports': [
        ([('host', 1), ('port', 1)], {}),
        ([('scope', 1), ('last_alive', 1)], {}),
    ],
    'nuclei_hits': [
        ([('template-id', 1), ('matcher-name', 1), ('matched-at', 1)], {}),
        ([('scope', 1)], {}),
        _TRIAGE_STATUS_INDEX,
    ],
    'nuclei_passive_hits': [
        ([('template-id', 1), ('matcher-name', 1), ('host', 1)], {'unique': True}),
        ([('scope', 1)], {}),
        _TRIAGE_STATUS_INDEX,
    ],
    'secret_hits': [
        ([('scope', 1), ('host', 1), ('rule_id', 1), ('secret_sha256', 1)], {'unique': True}),
        (
            [('scope', 1), ('host', 1), ('rule_id', 1), ('fingerprint', 1)],
            {'unique': True, 'partialFilterExpression': {'fingerprint': {'$type': 'string'}}},
        ),
        ([('scope', 1)], {}),
        _TRIAGE_STATUS_INDEX,
    ],
    'asn_suggestions': [
        ([('scope', 1), ('as_number', 1), ('cidr', 1)], {'unique': True}),
        ([('scope', 1)], {}),
    ],
    'scope_candidates': [
        ([('scope', 1), ('apex', 1)], {'unique': True}),
        ([('scope', 1)], {}),
    ],
    'alerts': [
        ([('created_at', 1)], {}),
        ([('source', 1), ('created_at', 1)], {}),
    ],
}


def ensure_indexes(db):
    for collection, specs in INDEXES.items():
        existing = {tuple(idx['key'].items()) for idx in db[collection].list_indexes()}
        for keys, options in specs:
            if tuple(keys) in existing:
                continue
            db[collection].create_index(keys, **options)
