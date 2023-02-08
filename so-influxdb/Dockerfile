FROM ghcr.io/security-onion-solutions/influxdb:2.6.1
LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="InfluxDB running in Docker container for use with Security Onion"

HEALTHCHECK --interval=5m --timeout=3s CMD nc -z localhost 8086 || exit 1
EXPOSE 8086
VOLUME /conf
VOLUME /log
VOLUME /var/lib/influxdb2

RUN mkdir -p /log
RUN mkdir -p /conf

COPY entrypoint.sh /redirect_to_file.sh
RUN groupmod -g 939 influxdb

ENTRYPOINT ["/redirect_to_file.sh"]
CMD ["/entrypoint.sh", "influxd"]