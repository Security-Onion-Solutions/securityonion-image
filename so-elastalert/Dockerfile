FROM ghcr.io/security-onion-solutions/elastalert-docker:latest-alt
LABEL maintainer "Security Onion Solutions, LLC"

ARG GID=933
ARG UID=933
ARG USERNAME=elastalert

RUN addgroup -g ${GID} ${USERNAME} && \
    adduser -D --uid ${UID} --ingroup ${USERNAME} \
      --home /opt/elastalert --no-create-home ${USERNAME}

COPY ./files /custom

RUN cp -fr /custom/* $(find /usr -name elastalert -type d) && rm -fr /custom

RUN sed -i -e '$s,$, >> /var/log/elastalert/stdout.log 2>> /var/log/elastalert/stderr.log,' /opt/elastalert/run.sh

USER ${USERNAME}
ENTRYPOINT ["/opt/elastalert/run.sh", "--verbose"]