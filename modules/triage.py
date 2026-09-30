"""Canonical triage-status schema shared across every writer of it.

AutoBB itself never writes this field — nothing in subs.py/fullscan.py sets or
reads it, and every up_fields list that refreshes a findings collection
deliberately excludes it (see the "keep 'triage' out of up_fields" comments in
subs.py/fullscan.py). It's set out-of-band, today by autobbmcp's
set_path_status/set_nuclei_status/set_secret_status write tools
(https://github.com/rivalsec/autobbmcp, mcp_server/writes.py), and later
potentially by autobb-webui once it grows a write path of its own (today it's
read-only by design — see its README's "AutoBB stays the sole writer").

This module exists so every writer/reader agrees on one definition instead of
each hardcoding its own copy of the enum and field shape. It's data only, no
behavior: it defines the schema, not who's allowed to set it.

Collections that carry this field, each keyed as noted (same keys the `get_*`
single-doc lookups in autobbmcp's mcp_server/db.py already use):
    http_paths            (url, path)
    nuclei_hits           (template-id, matched-at)
    nuclei_passive_hits   (template-id, matched-at), passive variant
    secret_hits           (host, rule_id, fingerprint)

Note: a nuclei_hits doc's true unique index also includes matcher-name (see
db_indexes.py) — (template-id, matched-at) is a simplification shared with
autobbmcp's get_nuclei_hit/set_nuclei_status, carrying the same rare-collision
caveat: two hits differing only by matcher-name on the same template+URL would
share one triage record.

Doc shape when present:
    triage: {
        status: str        # one of STATUS_VALUES
        note: str | None   # free-text reason, capped at 1000 chars by writers
        source: str        # who/what set it, e.g. "mcp", "webui"
        added_by: str       # human/agent identity within that source
        at: datetime
    }

A doc with no `triage` field at all is implicitly status "new" — callers
filtering by status should treat a missing field as "new", not as an error or
an excluded/unknown state.
"""
from __future__ import annotations

TRIAGE_FIELD = "triage"

# Closed set — keep in sync with autobbmcp's mcp_server/db.py STATUS_VALUES.
STATUS_VALUES = ("new", "confirmed", "false_positive")

TRIAGE_COLLECTIONS = ("http_paths", "nuclei_hits", "nuclei_passive_hits", "secret_hits")
