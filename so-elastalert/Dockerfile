FROM jertel/elastalert-docker:0.2.4
LABEL maintainer "Security Onion Solutions, LLC"

ARG GID=933
ARG UID=933
ARG USERNAME=elastalert

RUN addgroup -g ${GID} ${USERNAME} && \
    adduser -D --uid ${UID} --ingroup ${USERNAME} \
      --home /opt/elastalert --no-create-home ${USERNAME}

COPY ./files/* /usr/local/lib/python3.6/site-packages/elastalert/

USER ${USERNAME}
ENTRYPOINT ["/opt/elastalert/run.sh", "--verbose"]