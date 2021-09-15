#!/bin/bash

evtx2json -q /tmp/import.evtx
cat /tmp/import.json | jq -r '.[]."@timestamp"' | sort -r | head -n 1 > /tmp/oldest
cat /tmp/import.json | jq -r  '.[]."@timestamp"' | sort | head -n 1 > /tmp/newest