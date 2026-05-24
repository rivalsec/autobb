# AutoBB

Bug bounty automation pipeline. Discovers subdomains, probes HTTP services, scans ports, and runs nuclei vulnerability checks across configured scopes. Tracks asset changes in MongoDB and sends alerts on new findings.

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

subfinder, shuffledns, puredns, massdns, dnsx, dnsgen, httpx, naabu, nuclei, chromium

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
sudo docker run --rm -v $(pwd):/autobb --net autobbnet autobb
```

This runs the default mode with all flags enabled (see below).

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

All flags are optional. The default Docker CMD enables all of them.

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
