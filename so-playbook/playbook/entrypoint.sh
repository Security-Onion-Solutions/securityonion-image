#!/bin/bash

passenger start --nginx-config-template /passenger/passenger-nginx-config-template.erb --log-file /passenger/log/passenger.log &>/dev/null