# Golang tools build-env
FROM golang:1.20.2-alpine as build-env
RUN apk --no-cache add git build-base libpcap-dev
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.1.1
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.5.7
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.2.9
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@v1.0.9
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.1.4
RUN go install -v github.com/d3mondev/puredns/v2@latest

#Release
FROM python:alpine3.17
RUN apk --update --no-cache add ldns \
  && apk --no-cache --virtual .deps add ldns-dev \
                                        git \
                                        build-base \
  && git clone --branch=master \
               https://github.com/blechschmidt/massdns.git \
  && cd massdns \
  && make \
  && mv bin/massdns /usr/bin/massdns \
  && rm -rf /massdns \
  && apk del .deps
#for naabu
RUN apk --no-cache add nmap libpcap-dev bind-tools ca-certificates nmap-scripts

COPY --from=build-env /go/bin/shuffledns /usr/bin/shuffledns
COPY --from=build-env /go/bin/dnsx /usr/bin/dnsx
COPY --from=build-env /go/bin/naabu /usr/bin/naabu
COPY --from=build-env /go/bin/subfinder /usr/bin/subfinder
COPY --from=build-env /go/bin/httpx /usr/bin/httpx
COPY --from=build-env /go/bin/nuclei /usr/bin/nuclei
COPY --from=build-env /go/bin/puredns /usr/bin/puredns
ADD ./requirements.txt /requirements.txt
RUN pip install --no-cache-dir --no-cache -r requirements.txt

WORKDIR /autobb

ENTRYPOINT ["python", "subs.py"]
CMD ["--workflow-olds", "--dns-brute", "--dns-alts", "--ports", "--nuclei", "--ports-olds", "--passive"]
