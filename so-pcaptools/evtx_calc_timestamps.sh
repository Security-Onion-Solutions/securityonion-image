#!/bin/bash

# Convert EVTX to JSON
evtx2json -q "/tmp/data.evtx" --output-file /tmp/evtx/import.json

# Check for timeshift
if [[ -z "${SHIFTTS}" ]]; then
timeshift.py /tmp/evtx/import.json "${SHIFTTS}" event.created
else
# Ensure JSON is line-delimited
cat /tmp/evtx/import.json | jq -c .[] > /tmp/evtx/data.json
fi

# Remove older import file
[ -f /tmp/evtx/import.json ] && rm -f /tmp/evtx/import.json

# Capture oldest and newest event timestamps
cat /tmp/evtx/data.json | jq -r '.["@timestamp"]' | sort -r | head -n 1 > /tmp/oldest
cat /tmp/evtx/data.json | jq -r '.["@timestamp"]' | sort | head -n 1 > /tmp/newest
