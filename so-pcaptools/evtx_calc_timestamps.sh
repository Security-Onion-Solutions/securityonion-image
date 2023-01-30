!/bin/bash

# Convert EVTX to JSON
evtx2json -q "/tmp/data.evtx" --output-file /tmp/evtx/import.json

# Re-format JSON so that it is line-delimited
cat /tmp/evtx/import.json | jq -c .[] > /tmp/evtx/data.json

# Remove older import file
[ -f /tmp/evtx/import.json ] && rm -f /tmp/evtx/import.json

# Capture oldest and newest event timestamps
cat /tmp/evtx/data.json | jq -r '.["@timestamp"]' | sort -r | head -n 1 > /tmp/oldest
cat /tmp/evtx/data.json | jq -r '.["@timestamp"]' | sort | head -n 1 > /tmp/newest
