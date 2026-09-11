#!/bin/bash

set -e  # Exit on error

echo "[*] Checking for existing Rust installation..."

if command -v rustup &> /dev/null; then
    echo "[*] Rustup is already installed: $(rustup --version)"
    echo "[*] Rustc version: $(rustc --version)"
else
    echo "[*] Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    echo "[*] Rust installation complete."

    # Source the cargo environment to load Rust immediately
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
fi

# Ensure rustc and cargo are available in the current session
if ! command -v rustc &> /dev/null || ! command -v cargo &> /dev/null; then
    echo "[!] Error: Rust not found after install. Try opening a new shell or sourcing ~/.cargo/env manually."
    exit 1
fi

echo ""
echo "[*] Final check:"
rustc --version
cargo --version
