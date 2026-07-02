ARG PG_VERSION=17.10-alpine3.24

FROM ghcr.io/security-onion-solutions/postgres:$PG_VERSION
LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="PostgreSQL running in Docker container for use with Security Onion"

HEALTHCHECK --interval=1m --timeout=10s CMD pg_isready -U postgres || exit 1
EXPOSE 5432

RUN mkdir -p /log /conf

RUN apk update && apk upgrade && \
    apk add \
      postgresql-pgvector \
      postgresql-pg_cron \
      postgresql-pg_partman \
      shadow

RUN usermod -u 939 postgres && groupmod -g 939 postgres

COPY entrypoint.sh /entrypoint.sh
RUN chmod a+x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["postgres", "-c", "config_file=/conf/postgresql.conf"]
