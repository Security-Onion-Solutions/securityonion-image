FROM ghcr.io/security-onion-solutions/ubi9:9.7

RUN dnf update -y && \
    dnf install -y --nodocs ca-certificates && \
    dnf clean all

WORKDIR /root/

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

RUN dnf install -y --nodocs sudo gcc python3.14 python3.14-pip && \
    dnf clean all
RUN pip3.14 install opencanary==0.9.8

ENTRYPOINT ["/usr/local/bin/opencanaryd", "--dev", "--uid=nobody", "--gid=nobody"]