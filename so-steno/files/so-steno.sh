#!/bin/bash
exec >> /var/log/stenographer/stenographer.log 2>&1

# Generate the keys if they have not been already
/usr/bin/stenokeys.sh 941 939

chown -R 941:939 /etc/stenographer/certs

exec runuser -l stenographer -c 'exec /usr/bin/stenographer -v 1 --syslog=false' 
