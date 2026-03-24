#!/bin/bash

setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/zeek
setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/capstats

# Install custom Zeek packages from /opt/so/conf/zeek/zkg
CUSTOM_PKG_DIR="/opt/so/conf/zeek/zkg"
if [ -d "$CUSTOM_PKG_DIR" ]; then
  for pkg in "$CUSTOM_PKG_DIR"/*/; do
    [ -d "$pkg" ] || continue
    echo "Installing custom Zeek package: $pkg"
    git config --global --add safe.directory "$pkg"
    /opt/zeek/bin/zkg install --force --skiptests "$pkg"
  done
fi

runuser zeek -c '/opt/zeek/bin/zeekctl deploy'

trap "runuser zeek -c '/opt/zeek/bin/zeekctl stop'" SIGTERM
sleep infinity& wait; kill $!
