#!/bin/bash

# Redirect the official postgres entrypoint's output to /log/postgres.log.
# Role/DB provisioning lives in the salt-managed init-db.sh, not here.
exec docker-entrypoint.sh "$@" >> /log/postgres.log 2>&1
