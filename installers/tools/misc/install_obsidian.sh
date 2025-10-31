#!/bin/bash

# Function to check if Obsidian is installed
is_obsidian_installed() {
    command -v obsidian &> /dev/null
}

# Detect OS and Architecture
OS=$(uname -s)
ARCH=$(uname -m)

if is_obsidian_installed; then
    echo "Obsidian is already installed."
    exit 0
fi

case "$OS" in
    Linux)
        if [[ -f /etc/debian_version ]]; then
            echo "Detected Debian-based Linux. Installing Obsidian..."
            wget -O obsidian.deb "https://github.com/obsidianmd/obsidian-releases/releases/latest/download/Obsidian-amd64.deb"
            sudo dpkg -i obsidian.deb
            sudo apt-get install -f  # Fix dependencies if needed
            rm obsidian.deb
        elif [[ -f /etc/arch-release ]]; then
            echo "Detected Arch-based Linux. Installing Obsidian..."
            sudo pacman -Sy --noconfirm obsidian
        else
            echo "Unsupported Linux distribution. Install manually from: https://obsidian.md"
            exit 1
        fi
        ;;
    Darwin)
        echo "Detected macOS. Installing Obsidian..."
        brew install --cask obsidian
        ;;
    CYGWIN*|MINGW*|MSYS*)
        echo "Detected Windows. Downloading Obsidian installer..."
        OBSIDIAN_URL="https://github.com/obsidianmd/obsidian-releases/releases/latest/download/Obsidian.Setup.exe"
        INSTALLER="ObsidianSetup.exe"
        curl -L -o $INSTALLER $OBSIDIAN_URL
        start $INSTALLER
        echo "Run the installer manually."
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "Obsidian installation complete."

