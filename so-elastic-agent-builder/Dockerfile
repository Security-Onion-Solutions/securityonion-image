# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.

FROM alpine AS builder
ARG VERSION=8.7.0
ARG OOS='linux darwin windows'

RUN    wget https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${VERSION}-windows-x86_64.zip \
    && wget https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${VERSION}-darwin-x86_64.tar.gz \
    && wget https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${VERSION}-linux-x86_64.tar.gz \
    && unzip elastic-agent-*.zip \
    && for archive in *.tar.gz; do tar xf "$archive"; done \
    && rm -rf elastic-agent-*/data/elastic-agent-*/components/kibana \
    && rm -rf elastic-agent-*/data/elastic-agent-*/components/module* \
    && find elastic-agent-*/data/elastic-agent-*/components -regex '.*fleet.*\|.*packet.*\|.*apm*.*\|.*audit.*\|.*heart.*\|.*endpoint-security.*\|.*cloud.*' -delete \
    && for OS in $OOS; do rm -rf elastic-agent; mv elastic-agent-${VERSION}-${OS}-x86_64 elastic-agent; tar -czvf ${OS}.tar.gz elastic-agent; done \
    && touch "v${VERSION}"
    
FROM golang:1.19-alpine
ARG VERSION=8.7.0

RUN mkdir /workspace
ADD source /workspace
WORKDIR /workspace
RUN go get .

COPY --from=builder windows.tar.gz /workspace/files/elastic-agent/
COPY --from=builder darwin.tar.gz /workspace/files/elastic-agent/
COPY --from=builder linux.tar.gz /workspace/files/elastic-agent/
COPY --from=builder v${VERSION} /workspace/files/elastic-agent/