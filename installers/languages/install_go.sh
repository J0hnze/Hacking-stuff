#!/bin/bash

set -e  # Exit on error

GO_VERSION="1.22.3"  # Change this to the version you want
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"

echo "[*] Checking for existing Go installation..."
if command -v go &> /dev/null; then
    echo "[*] Go is already installed: $(go version)"
    exit 0
fi

echo "[*] Downloading Go ${GO_VERSION}..."
curl -LO "$GO_URL"

echo "[*] Extracting and installing Go..."
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "$GO_TAR"
rm "$GO_TAR"

# Set up Go environment
GOENV="$HOME/.goenv"
echo "[*] Writing Go environment variables to $GOENV..."

cat <<EOF > "$GOENV"
export GOROOT=/usr/local/go
export GOPATH=\$HOME/go
export PATH=\$PATH:\$GOROOT/bin:\$GOPATH/bin
EOF

# Source in this shell session
source "$GOENV"

echo ""
echo "Installation complete."
echo "Go version: $(go version)"
echo ""
echo "To make Go available in all sessions, add this line to your ~/.bashrc or ~/.zshrc:"
echo ""
echo "[ -f ~/.goenv ] && source ~/.goenv"
