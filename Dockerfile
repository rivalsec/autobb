# Tiny build stage just for massdns (no prebuilt release exists)
FROM debian:bookworm-slim AS massdns-build
RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential libldns-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch=master https://github.com/blechschmidt/massdns.git /massdns \
    && cd /massdns && make

# Prebuilt binaries (runs in parallel with massdns-build)
FROM debian:bookworm-slim AS bins
ARG TARGETOS
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN set -eux; \
    OS="${TARGETOS:-linux}"; ARCH="${TARGETARCH:-amd64}"; \
    curl -sSLO "https://github.com/projectdiscovery/naabu/releases/download/v2.4.0/naabu_2.4.0_${OS}_${ARCH}.zip"             && unzip -j "naabu_2.4.0_${OS}_${ARCH}.zip"        naabu; \
    curl -sSLO "https://github.com/projectdiscovery/subfinder/releases/download/v2.12.0/subfinder_2.12.0_${OS}_${ARCH}.zip"   && unzip -j "subfinder_2.12.0_${OS}_${ARCH}.zip"   subfinder; \
    curl -sSLO "https://github.com/projectdiscovery/httpx/releases/download/v1.8.1/httpx_1.8.1_${OS}_${ARCH}.zip"             && unzip -j "httpx_1.8.1_${OS}_${ARCH}.zip"        httpx; \
    curl -sSLO "https://github.com/projectdiscovery/nuclei/releases/download/v3.7.0/nuclei_3.7.0_${OS}_${ARCH}.zip"           && unzip -j "nuclei_3.7.0_${OS}_${ARCH}.zip"       nuclei; \
    curl -sSLO "https://github.com/projectdiscovery/shuffledns/releases/download/v1.2.1/shuffledns_1.2.1_${OS}_${ARCH}.zip"   && unzip -j "shuffledns_1.2.1_${OS}_${ARCH}.zip"   shuffledns; \
    curl -sSLO "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.3/dnsx_1.2.3_${OS}_${ARCH}.zip"               && unzip -j "dnsx_1.2.3_${OS}_${ARCH}.zip"         dnsx; \
    curl -sSL  "https://github.com/d3mondev/puredns/releases/download/v2.1.1/puredns-Linux-${ARCH}.tgz"                       | tar xz puredns; \
    curl -sSL  "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_${OS}_${ARCH}.tar.gz"                        | tar xz ffuf; \
    GLARCH="$([ "$ARCH" = "amd64" ] && echo x64 || echo "$ARCH")"; \
    curl -sSL  "https://github.com/gitleaks/gitleaks/releases/download/v8.23.2/gitleaks_8.23.2_linux_${GLARCH}.tar.gz"        | tar xz gitleaks; \
    rm -f *.zip; \
    chmod +x naabu subfinder httpx nuclei shuffledns dnsx puredns ffuf gitleaks

#Release
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 dnsutils ca-certificates nmap chromium \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bins          /dl/naabu             /usr/bin/naabu
COPY --from=bins          /dl/subfinder         /usr/bin/subfinder
COPY --from=bins          /dl/httpx             /usr/bin/httpx
COPY --from=bins          /dl/nuclei            /usr/bin/nuclei
COPY --from=bins          /dl/shuffledns        /usr/bin/shuffledns
COPY --from=bins          /dl/dnsx              /usr/bin/dnsx
COPY --from=bins          /dl/puredns           /usr/bin/puredns
COPY --from=bins          /dl/ffuf              /usr/bin/ffuf
COPY --from=bins          /dl/gitleaks          /usr/bin/gitleaks
COPY --from=massdns-build /massdns/bin/massdns  /usr/bin/massdns

ADD ./requirements.txt /requirements.txt
RUN pip install --no-cache-dir --no-cache -r requirements.txt

# keep ephemeral run artifacts (httprobes/, tmp/) off the bind-mounted /autobb
# so files don't end up host-owned by container-root; harvested/ stays on /autobb
ENV AUTOBB_RUNTIME_DIR=/var/autobb

WORKDIR /autobb

ENTRYPOINT ["python", "subs.py"]
CMD ["--workflow-olds", "--dns-brute", "--dns-alts", "--ports", "--nuclei", "--ports-olds", "--passive", "--http-fuzz", "--secrets"]
