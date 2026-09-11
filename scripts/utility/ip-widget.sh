#!/usr/bin/env bash

# Map allowed public IP addresses to names.
# Replace these example IPs with your real VPN addresses.
declare -A VPN_NAMES=(
    ["10.0.0.1/32"]="VPN 1"
    # ["198.51.100.0/24"]="Home VPN"
)

# Public IP lookup services
IP_SERVICES=(
    "https://api.ipify.org"
    "https://ifconfig.me/ip"
    "https://icanhazip.com"
)

PUBLIC_IP=""

# Try each service until one works
for SERVICE in "${IP_SERVICES[@]}"; do
    PUBLIC_IP=$(curl --silent --show-error --fail \
        --max-time 5 \
        "$SERVICE" 2>/dev/null | tr -d '[:space:]')

    if [[ "$PUBLIC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        break
    fi

    PUBLIC_IP=""
done

# Show red if the public IP could not be detected
if [[ -z "$PUBLIC_IP" ]]; then
    printf '🔴 No external IP\n'
    exit 0
fi

MATCHED_NAME=""

# Find the matching VPN network and name
for NETWORK in "${!VPN_NAMES[@]}"; do
    if python3 - "$PUBLIC_IP" "$NETWORK" <<'PY'
import sys
import ipaddress

try:
    ip = ipaddress.ip_address(sys.argv[1])
    network = ipaddress.ip_network(sys.argv[2], strict=False)
    sys.exit(0 if ip in network else 1)
except ValueError:
    sys.exit(1)
PY
    then
        MATCHED_NAME="${VPN_NAMES[$NETWORK]}"
        break
    fi
done

if [[ -n "$MATCHED_NAME" ]]; then
    printf '🟢 %s - %s\n' "$PUBLIC_IP" "$MATCHED_NAME"
else
    printf '🔴 %s - Unknown network\n' "$PUBLIC_IP"
fi
