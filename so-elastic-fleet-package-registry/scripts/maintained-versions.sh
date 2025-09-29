#!/bin/bash

SOURCE_DIR="/packages/package-storage"
DEST_DIR="/packages/saved-packages"

VERSION_DIR="/versions"

mkdir -p "$DEST_DIR"

for version_file in "$VERSION_DIR"/*.txt; do
    echo "Processing version file: $version_file"
    while IFS= read -r file || [[ -n "$file" ]]; do
        if [[ -f "$SOURCE_DIR/$file" ]]; then
            echo "Backing up $file to $DEST_DIR"
            cp -fv "$SOURCE_DIR/$file" "$DEST_DIR/"
            echo "Backing up signature file for $file to $DEST_DIR"
            cp -fv "$SOURCE_DIR/$file.sig" "$DEST_DIR"
        fi
    done < "$version_file"
done

