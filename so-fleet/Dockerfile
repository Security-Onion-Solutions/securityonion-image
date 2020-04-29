FROM alpine
LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Fleet running in Docker container for use with Security Onion"

RUN apk --update add ca-certificates unzip curl
RUN mkdir -p /tmp/fleet && cd /tmp/fleet \
&& curl -OL  https://github.com/kolide/fleet/releases/latest/download/fleet.zip \
&& unzip fleet.zip 'linux/*' \
&& cp linux/fleet /usr/bin/fleet \
&& cp linux/fleetctl /usr/bin/fleetctl \
&& cd /tmp && rm -rf /tmp/fleet

COPY startfleet.sh /startfleet.sh
RUN chmod +x /startfleet.sh

ENTRYPOINT ["/startfleet.sh"]
