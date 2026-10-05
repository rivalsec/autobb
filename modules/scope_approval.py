"""Human-approved apex domains -> live scope.

An apex reaches a scope two ways:

  1. `scope.domains` in config.yaml / scopes.yaml — the operator edits YAML.
  2. `scope_candidates` with `approval.status == "approved"` — the operator taps
     Approve on the Telegram alert bb-sandbox raises for a suggestion, or flips
     the switch in autobbui's Recon view. The decision is a Mongo field:
         approval: {status: "approved"|"declined", at: <datetime>, by: <str>}
     Absent `approval` means nobody has decided yet.

This module folds (2) into (1) so the rest of AutoBB cannot tell them apart. That
is the whole point: an approved apex must be recon'd, resolved, probed, fuzzed
and scanned exactly like one typed into the YAML, not merely tolerated. Because
every consumer reads `scope['domains']` off the list config.py builds, merging
there covers all of them at once:

    utils/common.domain_inscope   the in-scope test for every host
    subs.py recon_domains         subdomain enumeration (subfinder/puredns/brute)
    subs.py scope_parents         prefix extraction for brute force
    subs.py dnsx(scope['domains'])  the no-recon path
    juicy.py scope_parents        juicy-host scoring
    modules/scope_osint           seeds, AND the exclusion set — so an apex that
                                  is already approved stops being re-suggested

Suggestion stays one-way: AutoBB and the bb-sandbox agent only ever WRITE
candidates here; nothing in this repo sets `approval`. Only the operator does,
through Telegram or autobbui.
"""
import logging

APPROVED = 'approved'


def _norm(host):
    return (host or '').strip().lower().rstrip('.')


def approved_apexes(db):
    """{scope_name: [apex, ...]} for every human-approved candidate.

    One query for all scopes, not one per scope: config.py runs this at import on
    every AutoBB invocation and Mongo is often reached over a tunnel where the
    round trip costs more than the query.
    """
    out = {}
    cur = db['scope_candidates'].find(
        {'approval.status': APPROVED}, {'_id': 0, 'scope': 1, 'apex': 1})
    for doc in cur:
        scope, apex = doc.get('scope'), _norm(doc.get('apex'))
        if isinstance(scope, str) and scope and apex:
            out.setdefault(scope, set()).add(apex)
    return {scope: sorted(apexes) for scope, apexes in out.items()}


def apply_approved_apexes(scopes, db):
    """Merge approved apexes into each scope's `domains`, in place.

    Mutates the dicts config.py already built, so every module that does
    `from config import scopes` sees the merged list with no further wiring.
    Returns {scope_name: [apex, ...]} of what was actually added.

    Deliberately NOT fail-soft. Silently continuing on a read error would run a
    whole recon pass over a narrower scope than the operator approved, and that
    looks like success — the opposite of useful. config.py already requires a
    reachable Mongo at import (ensure_indexes), so this adds no new failure mode.
    """
    approved = approved_apexes(db)
    added = {}
    for scope in scopes:
        name = scope['name']
        want = approved.get(name)
        if not want:
            continue
        have = {_norm(d) for d in scope['domains']}
        new = [a for a in want if a not in have]
        if new:
            scope['domains'].extend(new)
            added[name] = new

    for name, apexes in sorted(added.items()):
        # The load-bearing audit line: these apexes are about to be enumerated and
        # scanned as in-scope, and they are not in anyone's YAML.
        logging.info("scope %s: +%d human-approved apex(es) from scope_candidates: %s",
                     name, len(apexes), ', '.join(apexes))

    # An approval for a scope AutoBB doesn't configure can't do anything here.
    # Say so: it is the obvious cause of "I approved it but nothing got scanned"
    # (e.g. the scope exists in the agent's mongo-discovered set but not in this
    # config.yaml), and it is otherwise invisible.
    unknown = set(approved) - {s['name'] for s in scopes}
    for name in sorted(unknown):
        logging.warning("ignoring %d approved apex(es) for unknown scope %r "
                        "(not in config.yaml scope list): %s",
                        len(approved[name]), name, ', '.join(approved[name]))
    return added
