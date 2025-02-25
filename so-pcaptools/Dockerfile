FROM oraclelinux:9-slim AS builder

ARG ARG PCAPFIX_VERSION=1.1.7

RUN microdnf update && microdnf install --enablerepo=ol9_appstream -y wireshark-cli gcc gcc-c++ make automake autoconf libtool cmake pkg-config &&\
    wget http://f00l.de/pcapfix/pcapfix-${PCAPFIX_VERSION}.tar.gz && \
    tar xf pcapfix-${PCAPFIX_VERSION}.tar.gz && \
    cd pcapfix-${PCAPFIX_VERSION} && \
    sed -i'' -e 's/OPTFLAGS =.* -D/OPTFLAGS = -include sys\/types.h -D/' Makefile && \
    make && \
    make install

FROM oraclelinux:9-slim

ADD evtx_calc_timestamps.sh /evtx_calc_timestamps.sh
ADD timeshift.py /timeshift.py

# libwiretap provided by wireshark-cli pkg
RUN chmod +x /timeshift.py && \
    chmod +x /evtx_calc_timestamps.sh && \
    microdnf update && \
    microdnf install --enablerepo=ol9_appstream -y jq git python3 python3-pip wireshark-cli && \
    pip3 install evtx elasticsearch==8.17.1 tqdm orjson importlib_metadata && \
    pip3 install evtx2es --no-dependencies && \
    microdnf clean all && \
    rm -rf /var/cache/* /var/lib/dnf/*

COPY --from=builder /usr/bin/pcapfix /usr/bin/
COPY --from=builder /usr/bin/capinfos /usr/bin/