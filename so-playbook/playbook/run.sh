#!/bin/bash
cd /usr/src/redmine || exit 1

passenger start --nginx-config-template /passenger/passenger-nginx-config-template.erb --log-file /passenger/log/passenger.log &>/dev/null