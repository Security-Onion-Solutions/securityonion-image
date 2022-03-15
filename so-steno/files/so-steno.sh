#!/bin/bash

# Generate the keys if they have not been already
/usr/bin/stenokeys.sh 941 939

chown -R 941:939 /etc/stenographer/certs

exec runuser -l stenographer -c 'exec >> /var/log/stenographer/stenographer.log 2>&1 /usr/bin/stenographer --syslog=false' 
