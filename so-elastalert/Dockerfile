FROM jertel/elastalert-docker:0.2.4
LABEL maintainer "Security Onion Solutions, LLC"

RUN addgroup -g 933 elastalert && \
    adduser -D --uid 933 --ingroup elastalert \
      --home /opt/elastalert --no-create-home \
      elastalert
USER elastalert

COPY ./files/* /usr/local/lib/python3.6/site-packages/elastalert/
