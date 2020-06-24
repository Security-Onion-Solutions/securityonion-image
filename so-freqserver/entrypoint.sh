#!/bin/sh

cd opt/freq_server/freq || exit
python freq_server.py -s 0 -ip 0.0.0.0 10004 freqtable2018.freq