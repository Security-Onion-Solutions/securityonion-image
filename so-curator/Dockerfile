FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"

# Create a common centos update layer
RUN yum update -y && \
    yum clean all

# Create user
RUN groupadd --gid 934 curator && \
      adduser --uid 934 --gid 934 \
      --home-dir /usr/share/curator --no-create-home \
      curator && \
    rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch

RUN apk add --no-cache curl grep gawk coreutils shadow bash

RUN yum update -y && \
    yum install -y elasticsearch-curator && \
    chown -R curator: /opt/elasticsearch-curator /usr/bin/curator* && \
    yum clean all

USER curator

ENV LC_ALL en_US.UTF-8

ENTRYPOINT ["/bin/bash"]
