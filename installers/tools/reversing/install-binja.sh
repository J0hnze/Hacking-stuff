#!/bin/bash

# Create the packages directory if it doesn't exist
mkdir -p ./pkgs

# Function to install Binary Ninja
install_binary_ninja() {
    echo "Installing Binary Ninja..."

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        BINJA_FILE="./pkgs/binaryninja-demo.deb"
        BINJA_URL="https://cdn.binary.ninja/installers/binaryninja-demo.deb"

        if [[ -f "$BINJA_FILE" ]]; then
            echo "Binary Ninja package already exists. Skipping download."
        else
            wget "$BINJA_URL" -O "$BINJA_FILE"
        fi

        sudo dpkg -i "$BINJA_FILE" || sudo apt-get install -f

    elif [[ "$OSTYPE" == "darwin"* ]]; then
        BINJA_FILE="./pkgs/BinaryNinja.dmg"
        BINJA_URL="https://cdn.binary.ninja/installers/binaryninja_free_macosx.dmg"

        if [[ -f "$BINJA_FILE" ]]; then
            echo "Binary Ninja package already exists. Skipping download."
        else
            curl -L "$BINJA_URL" -o "$BINJA_FILE"
        fi

        hdiutil attach "$BINJA_FILE"
        cp -R /Volumes/Binary\ Ninja/Binary\ Ninja.app /Applications/
        hdiutil detach /Volumes/Binary\ Ninja

    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        echo "Binary Ninja requires manual installation on Windows. Download it from: https://binary.ninja/downloads/"
    fi
}

# Function to install Ghidra
install_ghidra() {
    echo "Installing Ghidra..."

    GHIDRA_VERSION="11.3"
    GHIDRA_DATE="20250205"
    GHIDRA_FILE="./pkgs/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"
    GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"

    if [[ -f "$GHIDRA_FILE" ]]; then
        echo "Ghidra package already exists. Skipping download."
    else
        wget "$GHIDRA_URL" -O "$GHIDRA_FILE"
    fi

    if [[ "$OSTYPE" == "linux-gnu"* || "$OSTYPE" == "darwin"* ]]; then
        sudo unzip "$GHIDRA_FILE" -d /opt/
        echo "Ghidra installed in /opt/"

    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        unzip "$GHIDRA_FILE" -d C:\
        echo "Ghidra installed in C:\\"
    fi
}

# Prompt user for installation choice
echo "Which tool would you like to install?"
echo "1) Binary Ninja"
echo "2) Ghidra"
echo "3) Both"
echo "4) Exit"
read -p "Enter your choice (1-4): " choice

case $choice in
    1) install_binary_ninja ;;
    2) install_ghidra ;;
    3) install_binary_ninja && install_ghidra ;;
    4) echo "Exiting..."; exit 0 ;;
    *) echo "Invalid choice. Exiting..."; exit 1 ;;
esac

echo "Installation complete."
