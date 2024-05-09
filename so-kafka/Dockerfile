# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

FROM ghcr.io/security-onion-solutions/oraclelinux:9

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Kafka running in a docker container for use with Security Onion"

ARG KAFKA_DOWNLOAD=https://downloads.apache.org/kafka/3.7.0/
ARG KAFKA_TARNAME=kafka_2.13-3.7.0

ARG JOLOKIA_VERSION=2.0.2
ARG JOLOKIA_DOWNLOAD=https://github.com/jolokia/jolokia/releases/download/v${JOLOKIA_VERSION}/jolokia-${JOLOKIA_VERSION}-bin.tar.gz

RUN dnf update -y && \
    dnf install -y java-11-openjdk java-11-openjdk-devel curl && \
    dnf clean all

WORKDIR /

RUN groupadd --gid 960 kafka && \
    adduser --uid 960 --gid 960 kafka && \
    curl -O ${KAFKA_DOWNLOAD}${KAFKA_TARNAME}.tgz && \
    tar -xzf ${KAFKA_TARNAME}.tgz && \
    curl -LO ${JOLOKIA_DOWNLOAD} && \
    tar -xzf jolokia-${JOLOKIA_VERSION}-bin.tar.gz && \
    rm -f ${KAFKA_TARNAME}.tgz && \
    mv ${KAFKA_TARNAME} kafka && \
    rm -f jolokia-${JOLOKIA_VERSION}-bin.tar.gz && \
    mv jolokia-${JOLOKIA_VERSION} jolokia && \
    chown -R 960:960 kafka && \
    chown -R 960:960 jolokia

ADD files/jolokia.xml /jolokia/jolokia.xml

ENTRYPOINT ["/kafka/bin/kafka-server-start.sh", "/kafka/config/kraft/server.properties"]