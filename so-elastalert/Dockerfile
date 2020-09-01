FROM jertel/elastalert-docker:latest-jertelfork
LABEL maintainer "Security Onion Solutions, LLC"

ARG GID=933
ARG UID=933
ARG USERNAME=elastalert

RUN addgroup -g ${GID} ${USERNAME} && \
    adduser -D --uid ${UID} --ingroup ${USERNAME} \
      --home /opt/elastalert --no-create-home ${USERNAME}

COPY ./files/* /opt/elastalert/elastalert/

USER ${USERNAME}
ENTRYPOINT ["/opt/elastalert/run.sh", "--verbose"]