#!/bin/bash

# Generate the keys if they have not been already
/usr/bin/stenokeys.sh 941 941

chown -R 941:941 /etc/stenographer/certs

#runuser -l stenographer -c '/opt/sensoroni/sensoroni -config /opt/sensoroni/sensoroni.json && /usr/bin/stenographer -syslog=false >> /var/log/stenographer/stenographer.log 2>&1'
runuser -l stenographer -c '/opt/sensoroni/sensoroni -c /opt/sensoroni/sensoroni.json &'
runuser -l stenographer -c '/usr/bin/stenographer -syslog=false >> /var/log/stenographer/stenographer.log 2>&1' 
