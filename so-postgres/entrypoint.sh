#!/bin/bash

# Thin wrapper around the official postgres entrypoint: send all server output to
# /log/postgres.log (bind-mounted to /opt/so/log/postgres on the host, rotated by
# salt logrotate).
#
# Role/database/grant provisioning is owned entirely by the salt-managed
# init-db.sh -- run on fresh init via /docker-entrypoint-initdb.d and reconciled
# on every highstate by postgres.enabled (postgres_bootstrap_soc_db) -- so it is
# intentionally NOT duplicated here. Doing it here as well raced init-db.sh on
# fresh init and caused a duplicate-key CREATE ROLE failure.
#
# exec so postgres becomes PID 1 and receives signals (SIGTERM) directly.
exec docker-entrypoint.sh "$@" >> /log/postgres.log 2>&1
