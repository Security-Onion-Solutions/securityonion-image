#!/bin/sh
cd /opt/so/idstools/etc  || exit

idstools-rulecat --force

while true; do sleep 1; done
