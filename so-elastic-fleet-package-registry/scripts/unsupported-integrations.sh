#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# This script removes unsupported packages from our self-hosted Elastic Package Repo container image.
# It is meant to be used during the image build process.
#
# unsupported-integrations.txt supports two entry types:
#
#   Exact prefix  e.g. "apm"        - removes any file whose integration name is exactly "apm"
#                                     (i.e. the portion of the filename before the first "-")
#   Glob pattern  e.g. "*preview*"  - matched against the full filename using bash glob rules;
#                                     any entry containing a "*" or "?" is treated as a glob
#
# Lines starting with "#" and blank lines are ignored.

set -e

STORAGE_DIR="/packages/package-storage"
RULES_FILE="/scripts/unsupported-integrations.txt"

exact_prefixes=()
glob_patterns=()

while IFS= read -r line; do
	# Skip blank and comments
	[[ -z "$line" || "$line" == \#* ]] && continue

	if [[ "$line" == *'*'* || "$line" == *'?'* ]]; then
		glob_patterns+=("$line")
	else
		exact_prefixes+=("$line")
	fi
done <"$RULES_FILE"

removed=0

for file in "$STORAGE_DIR"/*; do
	[[ -e "$file" ]] || continue
	basename=$(basename "$file")
	prefix="${basename%%-*}"

	# Check exact prefix rules
	if [[ ${#exact_prefixes[@]} -gt 0 ]]; then
		for p in "${exact_prefixes[@]}"; do
			if [[ "$prefix" == "$p" ]]; then
				echo "Removing (prefix '$p'): $basename"
				rm -f "$file"
				((removed++)) || true
				continue 2
			fi
		done
	fi

	# Check glob pattern rules
	if [[ ${#glob_patterns[@]} -gt 0 ]]; then
		for g in "${glob_patterns[@]}"; do
			if [[ "$basename" == $g ]]; then
				echo "Removing (glob '$g'): $basename"
				rm -f "$file"
				((removed++)) || true
			fi
		done
	fi

done
