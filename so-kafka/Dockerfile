# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

FROM ghcr.io/security-onion-solutions/kafka:3.8.0

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Kafka running in a docker container for use with Security Onion"

ARG JOLOKIA_VERSION=2.1.0
ARG JOLOKIA_DOWNLOAD=https://github.com/jolokia/jolokia/releases/download/v${JOLOKIA_VERSION}/jolokia-${JOLOKIA_VERSION}-bin.tar.gz

WORKDIR /opt

USER root

RUN addgroup -g 960 kafka && \
    adduser -D --uid 960 --ingroup kafka kafka && \
    wget ${JOLOKIA_DOWNLOAD} && \
    tar -xzf jolokia-${JOLOKIA_VERSION}-bin.tar.gz && \
    rm -f jolokia-${JOLOKIA_VERSION}-bin.tar.gz && \
    mv jolokia-${JOLOKIA_VERSION} jolokia && \
    chown -R 960:960 kafka && \
    chown -R 960:960 jolokia

USER kafka

ADD files/jolokia.xml /opt/jolokia/jolokia.xml

ENTRYPOINT ["/opt/kafka/bin/kafka-server-start.sh", "/opt/kafka/config/kraft/server.properties"]
