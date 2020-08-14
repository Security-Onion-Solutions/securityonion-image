#!/bin/sh

# Let's initialize the DB if it hasn't been done
/usr/bin/fleet prepare db
/usr/bin/fleet serve >/dev/null 2>&1
