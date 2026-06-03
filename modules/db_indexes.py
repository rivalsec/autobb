"""Idempotent MongoDB index setup. Call ensure_indexes(db) once at startup.

Each entry: (keys, options). keys is a list of (field, direction) tuples.
"""

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
    ],
    'http_paths': [
        ([('url', 1), ('path', 1)], {}),
        ([('scope', 1), ('last_alive', 1)], {}),
    ],
    'ports': [
        ([('host', 1), ('port', 1)], {}),
        ([('scope', 1), ('last_alive', 1)], {}),
    ],
    'nuclei_hits': [
        ([('template-id', 1), ('matcher-name', 1), ('matched-at', 1)], {}),
        ([('scope', 1)], {}),
    ],
    'nuclei_passive_hits': [
        ([('template-id', 1), ('matcher-name', 1), ('host', 1)], {'unique': True}),
        ([('scope', 1)], {}),
    ],
    'secret_hits': [
        ([('scope', 1), ('host', 1), ('rule_id', 1), ('secret_sha256', 1)], {'unique': True}),
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
