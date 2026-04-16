#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# This script removes packages from /packages/package-storage that are not the latest
# version compatible with the given Kibana version, as determined by the EPR /search API.

set -e

COMPATIBLE_FILE="$1"
STORAGE_DIR="/packages/package-storage"

if [[ ! -f "$COMPATIBLE_FILE" ]]; then
	echo "ERROR: compatible packages file not found: $COMPATIBLE_FILE" >&2
	exit 1
fi

declare -A KEEP

# Keep packages returned by the kibana-version-filtered API query
while IFS= read -r pkg; do
	[[ -z "$pkg" ]] && continue
	KEEP["$pkg"]=1
	KEEP["${pkg}.sig"]=1
done <"$COMPATIBLE_FILE"

removed=0
kept=0
for file in "$STORAGE_DIR"/*.zip "$STORAGE_DIR"/*.zip.sig; do
	[[ -e "$file" ]] || continue
	basename=$(basename "$file")
	name_prefix="${basename%%-*}"

	# keep all endpoint-* versions (Elastic Defend)
	if [[ "$name_prefix" == "endpoint" ]]; then
		((kept++)) || true
		continue
	fi

	if [[ -n "${KEEP[$basename]}" ]]; then
		echo "Keeping  : $basename"
		((kept++)) || true
	else
		rm -f "$file"
		((removed++)) || true
	fi
done
