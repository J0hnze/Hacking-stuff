#!/usr/bin/env bash

# Check if the hosts.txt file exists
if [ ! -f hosts.txt ]; then
    echo "File hosts.txt not found!"
    exit 1
fi

# Create a backup of the original file
cp hosts.txt hosts.txt.bak

# Use sed to remove specified patterns
sed -i -e 's/www//g' \
       -e 's|https://||g' \
       -e 's|http://||g' \
       -e "s/'//g" \
       -e 's/"//g' hosts.txt

echo "Cleaning completed. Original file backed up as hosts.txt.bak"
