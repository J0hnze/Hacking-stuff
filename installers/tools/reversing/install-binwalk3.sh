# install_binwalk3.sh

#!/bin/bash

# Install Binwalk 3
if command -v binwalk &> /dev/null; then
    echo "Binwalk is already installed."
else
    echo "Installing Binwalk 3..."
    if ! command -v rustc &> /dev/null; then
        echo "Rust is not installed. Please install Rust first."
        exit 1
    fi
    cargo install binwalk
    echo "Binwalk 3 installation complete."
fi
