#!/usr/bin/env python3
"""Unit tests for the gitleaks secret-finder staging (modules/secrets.py).

Run with: pytest secrets_test.py
(imports config -> needs a reachable MongoDB, same as the other repo tests).
"""
import os
import shutil

from modules.secrets import stage_bodies, secrets_scan

REQ_SECRET = "AKIAIOSFODNN7EXAMPLE"      # AWS-key-shaped, placed in OUR request header
BODY_TEXT = '<html>data-site-key="7400bd5df8b843b28254659f1abcdef0"</html>'


def _write_fixture(tmpdir):
    """One httprobes-format file: secret only in the request header."""
    host_dir = os.path.join(tmpdir, "response", "example.com")
    os.makedirs(host_dir)
    path = os.path.join(host_dir, "x.txt")
    with open(path, "w") as f:
        f.write(
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            f"Authorization: Bearer {REQ_SECRET}\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            f"{BODY_TEXT}\r\n"
            "\r\n"
            "https://example.com/\r\n"
        )
    return path


def test_request_headers_stripped(tmp_path):
    """Our own request-header token must never reach the staged body."""
    src = str(tmp_path / "save")
    _write_fixture(src)
    staging = str(tmp_path / "bodies")
    src_map = stage_bodies(src, staging)

    assert len(src_map) == 1
    staged = open(os.path.join(staging, list(src_map)[0])).read()
    assert REQ_SECRET not in staged          # request stripped
    assert 'data-site-key' in staged         # response body kept


def _write_ffuf_fixture(tmpdir):
    """ffuf -od raw format: request line + Host, separator, then response.
    No trailing URL line, so url must be reconstructed from the request."""
    probe_dir = os.path.join(tmpdir, "ab12cd34ef56")
    os.makedirs(probe_dir)
    path = os.path.join(probe_dir, "resp")
    with open(path, "w") as f:
        f.write(
            "GET /admin/config.json HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "User-Agent: Fuzz Faster U Fool v2.1.0-dev\r\n"
            "Accept-Encoding: gzip\r\n"
            "\r\n"
            "\n"
            "---- ↑ Request ---- Response ↓ ----\n"
            "\n"
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"note":"body"}\r\n'
        )
    return path


def test_ffuf_url_from_request(tmp_path):
    """ffuf files (no trailing URL line) reconstruct url/host from the request."""
    src = str(tmp_path / "ffuf")
    _write_ffuf_fixture(src)
    staging = str(tmp_path / "bodies")
    src_map = stage_bodies(src, staging)

    meta = list(src_map.values())[0]
    assert meta["host"] == "target.example.com"
    assert meta["url"] == "https://target.example.com/admin/config.json"   # default https
    staged = open(os.path.join(staging, list(src_map)[0])).read()
    assert "Fuzz Faster U Fool" not in staged    # request stripped
    assert '"note":"body"' in staged             # response kept


def test_ffuf_scheme_from_probe(tmp_path):
    """ffuf URL takes its scheme from the matching httpx probe (http here)."""
    src = str(tmp_path / "ffuf")
    _write_ffuf_fixture(src)
    src_map = stage_bodies(src, str(tmp_path / "bodies"),
                           host_scheme={"target.example.com": "http"})
    assert list(src_map.values())[0]["url"] == "http://target.example.com/admin/config.json"


def test_attribution(tmp_path):
    """Findings map back to the source url/host via the staging map."""
    src = str(tmp_path / "save")
    _write_fixture(src)
    staging = str(tmp_path / "bodies")
    hits = secrets_scan(src, staging)

    assert hits, "expected at least one gitleaks finding in the body"
    h = hits[0]
    assert h["host"] == "example.com"
    assert h["url"] == "https://example.com/"
    assert h["secret"] and h["secret_sha256"]
    assert REQ_SECRET not in h["secret"]     # never the request token
