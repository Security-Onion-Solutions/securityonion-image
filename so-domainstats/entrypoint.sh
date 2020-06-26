#!/bin/sh

cd /opt/domain_stats || exit
python3 domain_stats.py -ip 0.0.0.0 20000 -a top-1m.csv --preload 0
