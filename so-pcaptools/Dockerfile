FROM ghcr.io/security-onion-solutions/python:3-slim AS builder

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Tools for use with PCAP & EVTX files"

ARG PCAPFIX_VERSION=1.1.4
# DEBIAN_FRONTEND=noninteractive is required for non-interactive install of tshark
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
RUN apt-get update && apt-get install -y --no-install-recommends build-essential wget && rm -rf /var/lib/apt/lists/*
RUN wget http://f00l.de/pcapfix/pcapfix-${PCAPFIX_VERSION}.tar.gz && \
    tar xf pcapfix-${PCAPFIX_VERSION}.tar.gz && \
    cd pcapfix-${PCAPFIX_VERSION} && \
    sed -i'' -e 's/OPTFLAGS =.* -D/OPTFLAGS = -include sys\/types.h -D/' Makefile && \
    make && \
    make install

FROM ghcr.io/security-onion-solutions/python:3-slim

ADD calculate_timestamp.sh /calculate_timestamp.sh
RUN chmod +x /calculate_timestamp.sh

# libwiretap11 is required for capinfo libaries
# jq is required for evtx timestamp script
RUN apt-get update && apt-get install -y --no-install-recommends --force-yes libwiretap11 git jq && rm -rf /var/lib/apt/lists/*
RUN pip3 install evtx elasticsearch tqdm orjson
RUN git clone --depth 1 --branch v1.4.6 https://github.com/sumeshi/evtx2es.git

COPY --from=builder /usr/bin/pcapfix /usr/bin/
COPY --from=builder /usr/bin/capinfos /usr/bin/