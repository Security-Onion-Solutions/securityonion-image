#!/bin/bash

AFPACKET=
if [ -n "$INTERFACE" ]; then
  AFPACKET=--af-packet=$INTERFACE
fi
# delete the old PID do Suricata will start
mkdir -p /var/run/suricata
chown 940:940 /var/run/suricata
chmod 770 /var/run/suricata
rm -rf /var/run/suricata.pid
# Start Suricata - --init-errors-fatal could be added to make it die if rules are wrong
/opt/suricata/bin/suricata -c /etc/suricata/suricata.yaml $AFPACKET --user=940 --group=940 --pidfile /var/run/suricata.pid -F /etc/suricata/bpf $@
