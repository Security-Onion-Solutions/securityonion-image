#!/bin/bash
exec "$@" &> /log/influxdb.log
