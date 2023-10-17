#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# This script removes unsupported packages from our self-hosted Elastic Package Repo container image.
# It is meant to be used during the image build process.

cd /packages/package-storage/
for file in *
do
    PATTERN=$(echo $file | cut -d "-" -f 1)-
    [[ ! $(grep -x "$PATTERN" /scripts/supported-integrations.txt) ]] && rm "$file" && echo "Deleted: $file..."
done

exit 0