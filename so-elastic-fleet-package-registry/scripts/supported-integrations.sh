#/bin/bash

cd /packages/package-storage/
for file in *
do
    PATTERN=$(echo $file | cut -d "-" -f 1)-
    [[ ! $(grep -x "$PATTERN" /scripts/supported-integrations.txt) ]] && rm "$file" && echo "Deleted: $file..."
done

exit 0