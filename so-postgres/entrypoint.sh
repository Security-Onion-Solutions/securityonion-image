#!/bin/bash

# Resolve *_FILE secret env vars before launching the upstream entrypoint, so
# the upstream handler sees POSTGRES_PASSWORD (from POSTGRES_PASSWORD_FILE) and
# our auth step below sees SO_POSTGRES_PASS (from SO_POSTGRES_PASS_FILE).
# Docker-standard: file contents are treated as the secret with no trimming
# beyond a single trailing newline, matching the upstream postgres image.
if [ -z "${SO_POSTGRES_PASS:-}" ] && [ -n "${SO_POSTGRES_PASS_FILE:-}" ] && [ -r "$SO_POSTGRES_PASS_FILE" ]; then
    SO_POSTGRES_PASS="$(< "$SO_POSTGRES_PASS_FILE")"
    export SO_POSTGRES_PASS
fi

# Start postgres via the official entrypoint in the background
docker-entrypoint.sh "$@" &>> /log/postgres.log &
PG_PID=$!

# Wait for postgres to be ready
for i in $(seq 1 30); do
    if pg_isready -U postgres -q 2>/dev/null; then
        break
    fi
    sleep 1
done

# Create or update the application user on every startup
# This ensures the user exists and password stays in sync with the pillar
if [ -n "$SO_POSTGRES_USER" ] && [ -n "$SO_POSTGRES_PASS" ] && pg_isready -U postgres -q 2>/dev/null; then
    psql -U postgres -d "$POSTGRES_DB" -c "
        DO \$\$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$SO_POSTGRES_USER') THEN
                EXECUTE format('CREATE ROLE %I WITH LOGIN PASSWORD %L', '$SO_POSTGRES_USER', '$SO_POSTGRES_PASS');
            ELSE
                EXECUTE format('ALTER ROLE %I WITH PASSWORD %L', '$SO_POSTGRES_USER', '$SO_POSTGRES_PASS');
            END IF;
        END
        \$\$;
        GRANT ALL PRIVILEGES ON DATABASE \"$POSTGRES_DB\" TO \"$SO_POSTGRES_USER\";
    " &>> /log/postgres.log
fi

# Wait for the postgres process
wait $PG_PID
