#! /bin/bash

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"
GO_VERSION="1.23.2"

case "$OS" in
    Linux*)
        if [ -f /etc/debian_version ]; then
            PKG_MANAGER="apt"
        elif [ -f /etc/redhat-release ]; then
            PKG_MANAGER="yum"
        else
            echo "Unsupported Linux distribution"
            exit 1
        fi
        GO_URL="https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz"
        ;;
    Darwin*)
        PKG_MANAGER="brew"
        GO_URL="https://golang.org/dl/go${GO_VERSION}.darwin-amd64.tar.gz"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Remove old Go installation
sudo rm -f /usr/bin/go /usr/local/bin/go
sudo rm -rf /usr/local/go ~/go

# Download and install Go
cd /tmp || exit
wget "$GO_URL" -O go.tar.gz
sudo tar -C /usr/local -xzf go.tar.gz

# Install Go using package manager (only for Linux distributions)
if [ "$OS" = "Linux" ]; then
    sudo $PKG_MANAGER install -y golang
elif [ "$OS" = "Darwin" ]; then
    brew install go
fi

# Set up environment variables
echo "export PATH=\$PATH:/usr/local/go/bin" >> "$HOME/.profile"
source "$HOME/.profile"

go version

