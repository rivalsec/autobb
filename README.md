# autobb
It's my solution for bugbounty automation

# Fix for "nf_conntrack: table full, dropping packet"
echo "net.netfilter.nf_conntrack_max=1048576" >> /etc/sysctl.conf

sysctl -p

# install docker
sudo apt-get update && sudo apt install -y docker.io

sudo usermod -aG docker $USER

# install mongo
docker run --restart=always --name bbmongodb -d mongo:latest

# get mongodb ip 
docker container inspect bbmongodb | grep "IPAddress"

# clone with github token 
git clone https://github.com/rivalsec/autobb.git

cd autobb

cp config.dist.yaml config.yaml

## edit  config
mkdir wordlists

cp ~/SecLists/Discovery/DNS/* ./wordlists/

# build
docker build -t autobb .

## install dnsvalidator
git clone https://github.com/vortexau/dnsvalidator.git

docker build -t dnsvalidator ./dnsvalidator

## run dnsvalidator (add to cron) 
docker run --rm -v /tmp:/dnsout -t dnsvalidator -threads 20 -o /dnsout/resolvers.txt && mv /tmp/resolvers.txt ./autobb/resolvers

# run autobb container
docker run --rm -v $(pwd):/autobb autobb --ports --ports-olds --dns-brute --dns-alts --workflow-olds --nuclei

# export assets from the database
docker run --rm -v $(pwd):/autobb --entrypoint python autobb ./export.py -h

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