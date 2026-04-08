#!/bin/bash
exec docker-entrypoint.sh "$@" &>> /log/postgres.log
