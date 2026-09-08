ARG SO_BASE

FROM ghcr.io/security-onion-solutions/ubi9:9.7 AS builder

ARG ELASTALERT_REPO=https://github.com/jertel/elastalert2.git
ARG ELASTALERT_REF=master

RUN dnf update -y && \
    dnf install -y --nodocs ca-certificates && \
    dnf clean all

RUN dnf install -y --nodocs gcc git libffi-devel python3.14 python3.14-pip python3.14-devel && \
    dnf clean all

RUN git clone --depth 1 -b "${ELASTALERT_REF}" "${ELASTALERT_REPO}" /tmp/elastalert

RUN pip3.14 install --no-cache-dir wheel setuptools && \
    pip3.14 install --no-cache-dir /tmp/elastalert

FROM ${SO_BASE}
LABEL maintainer="Security Onion Solutions, LLC"

ARG GID=933
ARG UID=933
ARG USERNAME=so-elastalert

RUN dnf install -y --nodocs jq python3.14 python3.14-pip && \
    dnf clean all

COPY --from=builder /usr/local /usr/local

RUN mkdir -p /opt/elastalert /var/log/elastalert && \
    echo "#!/bin/sh" > /opt/elastalert/run.sh && \
    echo "set -e" >> /opt/elastalert/run.sh && \
    echo "elastalert-create-index --config /opt/elastalert/config.yaml" >> /opt/elastalert/run.sh && \
    echo "elastalert --config /opt/elastalert/config.yaml \"\$@\" >> /var/log/elastalert/stdout.log 2>> /var/log/elastalert/stderr.log" >> /opt/elastalert/run.sh && \
    chmod +x /opt/elastalert/run.sh && \
    groupadd -g ${GID} ${USERNAME} && \
    useradd -u ${UID} -g ${GID} -M -b /opt/elastalert -s /sbin/nologin \
        -c "ElastAlert 2 User" ${USERNAME} && \
    chown -R ${USERNAME}:${USERNAME} /opt/elastalert /var/log/elastalert

COPY ./files /custom

RUN cp -fr /custom/* $(find /usr/local -name elastalert -type d) && rm -fr /custom

RUN sed -i 's|\"enabled\": \"false\"|\"enabled\": "true"|' /usr/local/lib/*/site-packages/elastalert/es_mappings/8/*elastalert.json

USER ${USERNAME}
ENV TZ="UTC"

WORKDIR /opt/elastalert
ENTRYPOINT ["/opt/elastalert/run.sh", "--verbose"]

