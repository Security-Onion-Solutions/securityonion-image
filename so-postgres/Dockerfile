ARG PG_VERSION=17

FROM ghcr.io/security-onion-solutions/postgres:$PG_VERSION
LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="PostgreSQL running in Docker container for use with Security Onion"

HEALTHCHECK --interval=1m --timeout=10s CMD pg_isready -U postgres || exit 1
EXPOSE 5432

RUN mkdir -p /log /conf

RUN groupmod -g 939 postgres

RUN apt update -y && \
    apt install -y \
      postgresql-17-pgvector \
      postgresql-17-cron \
      postgresql-17-partman && \
    apt clean -y && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod a+x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["postgres", "-c", "config_file=/conf/postgresql.conf"]
