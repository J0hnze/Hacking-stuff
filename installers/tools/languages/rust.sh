# install_rust.sh

#!/bin/bash

# Install Rust
if command -v rustc &> /dev/null; then
    echo "Rust is already installed."
else
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "Rust installation complete."
fi
