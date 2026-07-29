FROM ghcr.io/security-onion-solutions/ubi9:9.7

LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="PostgreSQL running in Docker container for use with Security Onion"

# Set PostgreSQL specific environment variables
# Reminder: Update the commit hash whenever the PostgreSQL version is upgraded.
ENV PG_MAJOR=17 \
    PG_VERSION=17.10 \
    ENTRYPOINT_COMMIT=4f9ced003ba58a854656ba150d146243d27ae3ac \
    PGDATA=/var/lib/postgresql/data \
    PATH=/usr/pgsql-17/bin:$PATH \
    LANG=en_US.utf8

RUN dnf update -y && \
    dnf install -y --nodocs ca-certificates && \
    dnf clean all

HEALTHCHECK --interval=1m --timeout=10s CMD pg_isready -U postgres || exit 1
EXPOSE 5432

# Install PostgreSQL 17, extensions, and shadow-utils/gosu/ca-certificates
RUN dnf install -y --nodocs shadow-utils && \
    dnf install -y --nodocs libicu python3-psycopg2 && \
    dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm && \
    dnf install -y --disablerepo=* --enablerepo=pgdg17 \
        postgresql17-server \
        pgvector_17 \
        pg_cron_17 \
        pg_partman_17 && \
    dnf clean all && \
    rm -rf /var/cache/dnf/*

# Install gosu for root stepping down
RUN curl -L -s https://github.com/tianon/gosu/releases/download/1.19/gosu-amd64 -o /usr/local/bin/gosu && \
    chmod +x /usr/local/bin/gosu

# Fetch and install the official postgres entrypoint script
RUN curl -L -s https://raw.githubusercontent.com/docker-library/postgres/${ENTRYPOINT_COMMIT}/docker-entrypoint.sh -o /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

RUN mkdir -p /log /conf "$PGDATA" /var/run/postgresql && \
    chown -R postgres:postgres /var/run/postgresql

RUN usermod -u 939 postgres && groupmod -g 939 postgres

COPY entrypoint.sh /entrypoint.sh
RUN chmod a+x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["postgres", "-c", "config_file=/conf/postgresql.conf"]
