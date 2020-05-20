#!/bin/bash

setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/zeek
setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/capstats
runuser zeek -c '/opt/zeek/bin/zeekctl deploy'
sleep infinity
