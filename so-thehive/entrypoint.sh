#!/bin/bash

rm -f /tmp/garbage_file
while ! wget -O /tmp/garbage_file "${ELASTICSEARCH_HOST}:9500" 2>/dev/null
do
	echo "Waiting for Elasticsearch..."
	rm -f /tmp/garbage_file
	sleep 1
done
rm -f /tmp/garbage_file
sleep 5

# Remove the old PID
rm -f /opt/thehive/RUNNING_PID

thehive
