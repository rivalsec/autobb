# Golang tools build-env
FROM golang:1.25-alpine3.22 AS build-env
RUN apk --no-cache add git build-base libpcap-dev ldns-dev \
    && cd / && git clone --depth 1 --branch=master https://github.com/blechschmidt/massdns.git && cd /massdns && make
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.4.0
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.12.0
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.8.1
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.7.0
RUN go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@v1.2.1
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3
RUN go install -v github.com/d3mondev/puredns/v2@latest
RUN go install -v github.com/ffuf/ffuf/v2@v2.1.0

#Release
FROM python:alpine3.17
RUN apk --update --no-cache add libpcap-dev bind-tools ca-certificates nmap-scripts chromium

COPY --from=build-env /go/bin/shuffledns /usr/bin/shuffledns
COPY --from=build-env /go/bin/dnsx /usr/bin/dnsx
COPY --from=build-env /go/bin/naabu /usr/bin/naabu
COPY --from=build-env /go/bin/subfinder /usr/bin/subfinder
COPY --from=build-env /go/bin/httpx /usr/bin/httpx
COPY --from=build-env /go/bin/nuclei /usr/bin/nuclei
COPY --from=build-env /go/bin/puredns /usr/bin/puredns
COPY --from=build-env /go/bin/ffuf /usr/bin/ffuf
COPY --from=build-env /massdns/bin/massdns /usr/bin/massdns
ADD ./requirements.txt /requirements.txt
RUN pip install --no-cache-dir --no-cache -r requirements.txt

# keep ephemeral run artifacts (httprobes/, tmp/) off the bind-mounted /autobb
# so files don't end up host-owned by container-root; harvested/ stays on /autobb
ENV AUTOBB_RUNTIME_DIR=/var/autobb

WORKDIR /autobb

ENTRYPOINT ["python", "subs.py"]
CMD ["--workflow-olds", "--dns-brute", "--dns-alts", "--ports", "--nuclei", "--ports-olds", "--passive", "--http-fuzz"]
