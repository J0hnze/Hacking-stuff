#!/bin/bash

# Check if a domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Install jq if not installed
if ! command -v jq &>/dev/null; then
    echo "jq not found, installing..."
    sudo apt update && sudo apt install -y jq
fi

# Fetch data from crt.sh, extract unique common names, and save to subdomains.txt
curl -s "https://crt.sh/?q=$1&output=json" | jq -r '.[].common_name' | sort -u > subdomains.txt

echo "Unique subdomains saved to subdomains.txt"
