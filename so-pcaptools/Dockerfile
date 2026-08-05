ARG SO_BASE

FROM ghcr.io/security-onion-solutions/ubi9:9.7 AS builder

LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="Tools for use with PCAP & EVTX files"

ARG PCAPFIX_VERSION=1.1.7
RUN dnf install -y gcc make wget && dnf clean all && rm -rf /var/cache/dnf/*
RUN wget https://github.com/Rup0rt/pcapfix/archive/refs/tags/v${PCAPFIX_VERSION}.tar.gz && \
    tar xf v${PCAPFIX_VERSION}.tar.gz && \
    cd pcapfix-${PCAPFIX_VERSION} && \
    sed -i'' -e 's/OPTFLAGS =.* -D/OPTFLAGS = -include sys\/types.h -D/' Makefile && \
    make && \
    make install

FROM ${SO_BASE}

ADD evtx_calc_timestamps.sh /evtx_calc_timestamps.sh
RUN chmod +x /evtx_calc_timestamps.sh

ADD timeshift.py /timeshift.py
RUN chmod +x /timeshift.py

# libwiretap/wireshark-cli is required for capinfos; jq is required for evtx timestamp script
RUN dnf install -y --repofrompath=rocky-baseos,https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/ \
    --repofrompath=rocky-appstream,https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/ \
    --setopt=rocky-baseos.gpgcheck=0 \
    --setopt=rocky-appstream.gpgcheck=0 \
    wireshark-cli jq python3-pip && \
    dnf clean all && rm -rf /var/cache/dnf/*
RUN pip3 install evtx elasticsearch==7.17.1 tqdm orjson importlib_metadata
RUN pip3 install evtx2es --no-dependencies

COPY --from=builder /usr/bin/pcapfix /usr/bin/

