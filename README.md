# AutoBB
It's my solution for bugbounty automation

# Quick start guide

1) install docker:
```bash
sudo snap install docker
## OR ##
# curl -fsSL https://get.docker.com -o install-docker.sh
# sudo sh install-docker.sh
```

2) run mongodb container:
```bash
sudo docker run -d -p 127.0.0.1:27017:27017 --net autobbnet --name bbmongodb mongodb/mongodb-community-server:latest
```

3) get autobb:
```bash
git clone https://github.com/rivalsec/autobb.git
cd autobb
cp config.dist.yaml config.yaml
```

4) edit scope and alert sections in config.yaml:
```bash
nano config.yaml
```

5) build docker image:
```bash
sudo docker build -t autobb .
```
This will take some time...

6) run autobb scan in basic(light) mode:

```bash
sudo docker run --rm -v $(pwd):/autobb --net autobbnet autobb --ports --ports-olds --dns-brute --dns-alts --workflow-olds --nuclei
```
In this mode, only new or modified assets will be scanned.

## Run autobb in full scan mode
```bash
sudo docker run --rm -v $(pwd):/autobb  --net autobbnet --entrypoint python autobb fullscan.py
```

## Export assets from the database
```bash
sudo docker run --rm -v $(pwd):/autobb  --net autobbnet --entrypoint python autobb ./export.py -h
```

```
usage: export.py [-h] [-g {scopes,domains,ports,http_probes}] [-s SCOPE]
                 [-l LAST_ALIVE] [-p PRINT_FIELD]

exporter

options:
  -h, --help            show this help message and exit
  -g {scopes,domains,ports,http_probes}, --get {scopes,domains,ports,http_probes}
                        get one of (default: None)
  -s SCOPE, --scope SCOPE
                        scope to get, if not - all scopes (default: None)
  -l LAST_ALIVE, --last-alive LAST_ALIVE
                        days then last time was alive (default: 30)
  -p PRINT_FIELD, --print-field PRINT_FIELD
                        object field to print, object json if not set
                        (default: None)
```

# FAQ
## Use dnsvalidator to get a fresh resolvers file
```bash
git clone https://github.com/vortexau/dnsvalidator.git
sudo docker build -t dnsvalidator ./dnsvalidator
## run dnsvalidator (add to crontab)
sudo docker run --rm -v /tmp:/dnsout -t dnsvalidator -threads 20 -o /dnsout/resolvers.txt && mv /tmp/resolvers.txt ./autobb/resolvers
```

## Fix for "nf_conntrack: table full, dropping packet"
```bash
echo "net.netfilter.nf_conntrack_max=1048576" >> /etc/sysctl.conf
sysctl -p
```