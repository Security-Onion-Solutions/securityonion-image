FROM ghcr.io/security-onion-solutions/influxdb:2.6.1
LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="InfluxDB running in Docker container for use with Security Onion"

HEALTHCHECK --interval=5m --timeout=3s CMD nc -z localhost 8086 || exit 1
EXPOSE 8086
VOLUME /var/lib/influxdb2

RUN mkdir -p /var/log
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["influxd"]
