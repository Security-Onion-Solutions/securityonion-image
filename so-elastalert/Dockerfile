FROM ghcr.io/jertel/elastalert2/elastalert2:2.2.2
LABEL maintainer "Security Onion Solutions, LLC"

ARG GID=933
ARG UID=933
ARG USERNAME=so-elastalert

USER root

RUN groupadd -g ${GID} ${USERNAME} && \
    useradd -u ${UID} -g ${GID} -M -b /opt/elastalert -s /sbin/nologin \
        -c "ElastAlert 2 User" ${USERNAME}

COPY ./files /custom

RUN cp -fr /custom/* $(find /usr -name elastalert -type d) && rm -fr /custom

RUN sed -i -e '$s,$, >> /var/log/elastalert/stdout.log 2>> /var/log/elastalert/stderr.log,' /opt/elastalert/run.sh

USER ${USERNAME}
ENTRYPOINT ["/opt/elastalert/run.sh", "--verbose"]