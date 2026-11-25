FROM ghcr.io/security-onion-solutions/valkey:9.1.4-alpine
LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="Valkey running in Docker container for use with Security Onion"
RUN addgroup -g 939 socore && adduser -D --uid 939 --ingroup socore socore && \
    chown 939:939 /data && \
    ln -sf valkey-server /usr/local/bin/redis-server && \
    ln -sf valkey-cli /usr/local/bin/redis-cli && \
    test -x /usr/local/bin/redis-server && test -x /usr/local/bin/redis-cli
VOLUME /data
WORKDIR /data
EXPOSE 6379
CMD ["redis-server"]
