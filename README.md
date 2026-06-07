# AutoBB

**Continuous external attack surface monitoring & vulnerability automation — self-hosted, runs continuously in Docker.**

AutoBB discovers your internet-facing assets, tracks how they change over time, scores findings by risk, scans them for vulnerabilities, and alerts you on anything new. It keeps a persistent asset inventory in MongoDB and re-checks it on a schedule, so it's a continuous monitor — not a one-shot recon script. Built for **bug bounty hunters** (be first to a new or changed asset on a large program) and **security teams / companies** (know your external attack surface and get alerted the moment it shifts).

Core loop: *discover assets → track changes → score risk → scan for vulns → alert.*

## What it does

- **Continuous asset discovery** — passive OSINT (subfinder), DNS brute-force (puredns), permutations (dnsgen), and resolution (dnsx) to find subdomains and live hosts.
- **Persistent asset inventory** — every domain, HTTP service, open port, and finding is stored in MongoDB (`domains`, `http_probes`, `ports`, `nuclei_hits`, `nuclei_passive_hits`, `http_paths`, `secret_hits`).
- **Change detection** — diffs each scan against the last and records a per-field diff history, so you're alerted on real changes and not re-alerted on oscillating values (e.g. rotating CDN CNAMEs).
- **Risk scoring ("juicy")** — surfaces the interesting findings first: out-of-scope CNAMEs/certs, services on non-80/443 ports, external redirects, fuzzed paths that flipped `4xx → 200`, and more.
- **Vulnerability scanning** — Nuclei in active, passive (against saved responses), and network-template modes.
- **Content discovery** — directory/file bruteforce (ffuf) on newly discovered alive HTTP services.
- **Secret scanning** — passive scan (gitleaks) over the response bodies AutoBB already saved from httpx/ffuf, so no extra requests are sent to targets. Findings are deduplicated, mapped back to their source URL/host, and labelled with a configurable severity policy (gitleaks has no native severity).
- **Scheduled rescans / continuous mode** — configurable rescan intervals plus `--workflow-olds` / `--ports-olds` to re-probe known assets; designed to run continuously in Docker.
- **Multi-channel alerts** — Telegram, SMTP, and VK Teams, with automatic large-message attachment fallback.
- **Considerate scanning, spread across assets** — AutoBB is built to avoid harming the assets it touches by distributing each scan across many targets in a single run, rather than concentrating load on any one host or name server:
  - **Subdomain brute-force** resolves names for *all scopes together in one shuffled, volume-capped run*, so DNS queries don't overflow any single authoritative name server (rate-limited via puredns).
  - **HTTP probing** runs across all scopes' hosts from one shared pool — any single host sees roughly one request.
  - **Port scanning** is rate-limited and skips CDN ranges.
  - **Vuln & content scanning** stay gentle per host by default: ffuf uses **1 thread per target** and Nuclei runs **one template at a time across many hosts** (`-c 1 -bs 100`), so each host gets one request at a time while the scan spreads across the host set.

  Every concurrency/rate knob is tunable — turn it up for speed when a target can take it.
- **Identifiable, self-hosted scanning** — set a single User-Agent / custom headers (e.g. `X-Bug-Bounty`) applied to every tool, and keep all collected data in your own infrastructure.

## Who it's for

**Bug bounty hunters**
- Continuously monitor large programs instead of re-running recon by hand.
- Get pinged the moment a new or changed asset appears — be first to it.
- Risk scoring surfaces the juicy targets so you don't dig through noise.
- No infra babysitting: it runs on its own in Docker and alerts you.

**Security teams & companies**
- Know your internet-facing attack surface (EASM) and catch shadow IT / forgotten subdomains.
- Get alerted on new exposures and changes as they happen.
- Continuous Nuclei vulnerability monitoring across all known assets.
- Fully self-hosted — data never leaves your infrastructure.
- Identifiable scan traffic via custom headers, and considerate-by-default scanning that won't overload production hosts (tunable up when you want speed).

## Web UI

A companion **read-only** web dashboard — [rivalsec/autobb-webui](https://github.com/rivalsec/autobb-webui) — visualizes everything AutoBB writes to MongoDB: the asset inventory (domains, HTTP services, ports, paths), vulnerability findings with severity filtering, per-host drilldown, and alert history. It only reads — AutoBB stays the sole writer — and is built on FastAPI + React, with optional token auth.

Quick demo (spins up the UI against a sample dataset):

```bash
curl -fsSL https://raw.githubusercontent.com/rivalsec/autobb-webui/main/demo/docker-compose.yml | docker compose -f - -p autobb-demo up
# then open http://127.0.0.1:8000
```

To point it at your own data, set `MONGO_URI` / `MONGO_DB` (use read-only MongoDB credentials and keep it bound to loopback). See the [autobb-webui](https://github.com/rivalsec/autobb-webui) repo for full setup.

## Architecture

```
subs.py          Main recon pipeline (subdomain enum, HTTP probing, port scan, nuclei)
fullscan.py      Full nuclei scan on all known alive hosts
export.py        Export assets from the database
config.yaml      Runtime configuration (copy from config.dist.yaml)
scopes.yaml      Optional separate scopes file (included via !include)
modules/
  alerts/        Alert backends: telegram, vkteams, smtp
  domain.py      Domain/subdomain logic
  http.py        HTTP probing
  httpfuzz.py    HTTP fuzzing
  port.py        Port scanning
  vulns.py       Nuclei scanning and template management
```

### Tools (bundled in Docker image)

subfinder, shuffledns, puredns, massdns, dnsx, dnsgen, httpx, naabu, nuclei, ffuf, gitleaks, chromium

## Quick start

### 1. Install Docker

```bash
sudo snap install docker
# or: curl -fsSL https://get.docker.com | sh
```

### 2. Start MongoDB

```bash
sudo docker network create autobbnet
sudo docker run -d -p 127.0.0.1:27017:27017 --net autobbnet --name bbmongodb mongodb/mongodb-community-server:latest
```

### 3. Clone and configure

```bash
git clone https://github.com/rivalsec/autobb.git
cd autobb
cp config.dist.yaml config.yaml
nano config.yaml
```

Edit at minimum:
- `scope` -- target domains/CIDRs
- `alerts` -- notification backend(s)

### 4. Build the Docker image

```bash
sudo docker build -t autobb .
```

### 5. Run a scan

```bash
sudo docker run --rm -v $(pwd):/autobb --init --shm-size=2g --net autobbnet autobb
```

This runs the default mode with all flags enabled (see below).

`--init` runs a small init process (tini) as PID 1 so the many short-lived child processes spawned by the pipeline (subfinder, httpx, nuclei, naabu, chromium, ...) get reaped properly and signals are forwarded; without it zombie processes accumulate and Ctrl-C may not stop the container cleanly. 

`--shm-size=2g` enlarges `/dev/shm` (default 64 MB), which the headless chromium used for screenshots/JS rendering needs for inter-process shared memory -- it crashes under load on the default size.

## Usage

### subs.py -- recon pipeline

```
docker run --rm -v $(pwd):/autobb --net autobbnet autobb [FLAGS]
```

| Flag | Description |
|------|-------------|
| `--dns-brute` | Bruteforce subdomains with wordlist |
| `--dns-alts` | Try permutated/alternative subdomains based on found ones |
| `--workflow-olds` | Re-probe old subdomains to detect changes |
| `--ports` | Scan ports on new hosts (top 1000 new, top 100 old) |
| `--ports-olds` | Rescan ports on previously known hosts |
| `--nuclei` | Run nuclei templates on new findings |
| `--passive` | Run passive nuclei checks |
| `--http-fuzz` | Bruteforce dirs/files (ffuf) on new alive HTTP probes |
| `--secrets` | Passive secret scan (gitleaks) of saved httpx/ffuf responses |
| `--no-subfinder` | Skip the subfinder (passive OSINT) step in subdomain enumeration |

All flags are optional. The default Docker CMD enables every flag except `--no-subfinder`.

**Light scan** (only new/modified assets):
```bash
sudo docker run --rm -v $(pwd):/autobb --init --shm-size=2g --net autobbnet autobb --ports --dns-brute --nuclei
```

### fullscan.py -- full vulnerability scan

Runs nuclei (high/critical) on all hosts alive within the configured window.

```bash
sudo docker run --rm -v $(pwd):/autobb --init --shm-size=2g --net autobbnet --entrypoint python autobb fullscan.py
```

### export.py -- database export

```bash
sudo docker run --rm -v $(pwd):/autobb --net autobbnet --entrypoint python autobb export.py [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-g {scopes,domains,ports,http_probes}` | Collection to export |
| `-s SCOPE` | Filter by scope name (default: all configured scopes) |
| `-a DAYS` | Only items added within N days |
| `-l DAYS` | Only items alive within N days (default: 30) |
| `-p FIELD` | Print single field instead of full JSON |

Examples:
```bash
# List all live domains for a scope
export.py -g domains -s hackerone -p host

# Recent HTTP probes as JSON
export.py -g http_probes -l 7

# Domains added in the last 2 days
export.py -g domains -a 2 -p host
```

## Configuration

Copy `config.dist.yaml` to `config.yaml`. Key sections:

### Scope

```yaml
scope:
  - name: hackerone
    domains: [hackerone.com]
    # subs_recon: true          # enabled by default
    # cidr: [127.0.0.1/32]
    # ips: [1.2.3.4]
    # domains_file: extra_domains.txt
    # cidr_file: extra_cidrs.txt
    # ips_file: extra_ips.txt
    # sub_refilters:            # regex filters to exclude subdomains
    #   - \.(stage|dev)\.hackerone\.com$
```

Scopes can also be split into a separate file:
```yaml
scope: !include ./scopes.yaml
```

### Alerts

Supports one or multiple backends simultaneously.

```yaml
alerts:
  use: telegram              # single backend
  # use: [telegram, smtp]   # multiple backends

  telegram:
    token: "BOT_TOKEN"
    chat_id: "CHAT_ID"
    msg_max_size: 4000

  vkteams:
    host: myteam.corp.com
    token: "BOT_TOKEN"
    chat_id: "CHAT_ID"
    msg_max_size: 1000

  smtp:
    host: smtp.example.com
    port: 587
    tls: true                # STARTTLS (port 587)
    ssl: false               # implicit SSL (port 465)
    username: user@example.com
    password: "APP_PASSWORD"
    from: autobb@example.com
    to:
      - me@example.com
    subject: autobb alert
    msg_max_size: 4000
    timeout: 30
```

When `msg_max_size` is exceeded, the full message is sent as a `.txt` file attachment (telegram/smtp) or uploaded file (vkteams).

### Nuclei

Custom templates can be added alongside the bundled `nuclei-templates/`:
```yaml
nuclei:
  cmd: ['nuclei', '-no-color', '-jsonl', '-t', './nuclei-templates', '-t', './nuclei-my-templates']
  exclude_templates:
    - ./nuclei-templates/http/technologies/tech-detect.yaml
```

### Secrets

Passive secret scanning runs gitleaks over the HTTP response bodies already saved by httpx/ffuf (request headers are stripped first, so your own custom headers are never matched). gitleaks has no native severity, so AutoBB applies its own `severity` policy to sort and label alerts.

```yaml
secrets:
  cmd: ['gitleaks', 'dir', '--no-banner', '-f', 'json']
  # config: './autobb-secrets.toml'   # optional custom gitleaks ruleset (-> gitleaks -c <file>)
  filter: []            # regexes to drop noisy rule_ids / matches / urls
  weird_threshold: 50   # drop all hits from a single host above this (0 disables)
  severity:
    default: medium     # applied to any rule_id not listed below
    critical:
      - private-key
      - aws-access-token
      - gcp-api-key
    high:
      - github-pat
      - slack-bot-token
      - stripe-access-token
      - telegram-bot-api-token
      - jwt
    low:
      - generic-api-key   # noisy: also matches public reCAPTCHA/site keys
```

### Alert filters

Filter out noisy nuclei findings from notifications:
```yaml
juicer_filters:
  cname: []
  tls_dns: []
  title404: []
  location: []
```

## FAQ

### Fresh resolvers with dnsvalidator

```bash
git clone https://github.com/vortexau/dnsvalidator.git
sudo docker build -t dnsvalidator ./dnsvalidator
sudo docker run --rm -v /tmp:/dnsout -t dnsvalidator -threads 20 -o /dnsout/resolvers.txt
mv /tmp/resolvers.txt ./resolvers
```

### Fix "nf_conntrack: table full, dropping packet"

```bash
echo "net.netfilter.nf_conntrack_max=1048576" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```
