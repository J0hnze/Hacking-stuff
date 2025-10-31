#!/bin/bash

set -e  # Exit on error

echo "[*] Updating package lists..."
sudo apt update

echo "[*] Installing system dependencies..."
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    liblzma-dev \
    libx11-dev \
    libxcb1-dev \
    libxrandr-dev \
    libxi-dev \
    libx11-xcb-dev \
    git \
    curl \
    python3-pip

echo "[*] Checking for Rust toolchain..."
if ! command -v rustup &> /dev/null; then
    echo "[*] Rust not found. Installing Rust using rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "[*] Rust is already installed: $(rustc --version)"
fi

# Ensure Rust is available in this session
if ! command -v rustc &> /dev/null; then
    source "$HOME/.cargo/env"
fi

rustc --version
cargo --version

echo "[*] Installing Python tools for firmware analysis..."
pip3 install --upgrade pip
pip3 install uefi_firmware jefferson ubi-reader

echo "[*] Cloning binwalkv3 repository..."
mkdir -p ~/tools
cd ~/tools

if [ ! -d "binwalkv3" ]; then
    git clone https://github.com/iotsrg/binwalkv3.git
else
    echo "[*] binwalkv3 already cloned."
fi

cd binwalkv3

echo "[*] Building binwalkv3 with Cargo..."
cargo build --release

echo "[*] Creating alias in ~/.aliases..."
ALIAS_CMD='alias binwalk="$HOME/tools/binwalkv3/target/release/binwalk"'
ALIASES_FILE="$HOME/.aliases"

if ! grep -Fxq "$ALIAS_CMD" "$ALIASES_FILE"; then
    echo "$ALIAS_CMD" >> "$ALIASES_FILE"
    echo "[+] Alias added to $ALIASES_FILE"
else
    echo "[*] Alias already exists in $ALIASES_FILE"
fi

echo ""
echo "Installation complete"
echo ""
