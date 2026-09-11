#!/usr/bin/env nix-shell
#! nix-shell -i bash -p python3 python3Packages.ds-store

set -euo pipefail

FILE="${1:-}"

if [[ -z "$FILE" || ! -f "$FILE" ]]; then
  echo "Usage: $0 <.DS_Store file>"
  exit 1
fi

echo "[+] Reading .DS_Store: $FILE"
echo

python3 <<EOF
from ds_store import DSStore

with DSStore.open("$FILE", "r") as d:
    for entry in d:
        print(entry.filename)
EOF
