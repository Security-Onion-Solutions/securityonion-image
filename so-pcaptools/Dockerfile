FROM ghcr.io/security-onion-solutions/alpine:latest AS builder

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Tools for use with PCAP files"

ARG PCAPFIX_VERSION=1.1.4
RUN apk add build-base
RUN wget http://f00l.de/pcapfix/pcapfix-${PCAPFIX_VERSION}.tar.gz && \
    tar xf pcapfix-${PCAPFIX_VERSION}.tar.gz && \
    cd pcapfix-${PCAPFIX_VERSION} && \
    sed -i'' -e 's/OPTFLAGS =.* -D/OPTFLAGS = -include sys\/types.h -D/' Makefile && \
    make && \
    make install

FROM ghcr.io/security-onion-solutions/alpine:latest

RUN apk add wireshark-common 

COPY --from=builder /usr/bin/pcapfix /usr/bin/
