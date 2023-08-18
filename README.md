# autobb
It's my solution for bugbounty automation

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
