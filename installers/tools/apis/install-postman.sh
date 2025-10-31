#!/bin/bash

# Check system architecture
ARCH=$(uname -m)

# Determine download URL based on architecture
if [ "$ARCH" == "x86_64" ]; then
    DOWNLOAD_URL="https://dl.pstmn.io/download/latest/linux_64"
    echo "Detected x64 architecture, downloading the 64-bit version of Postman."
elif [ "$ARCH" == "aarch64" ]; then
    DOWNLOAD_URL="https://dl.pstmn.io/download/latest/linux_arm64"
    echo "Detected ARM64 architecture, downloading the ARM64 version of Postman."
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

# Download Postman
echo "Downloading Postman from $DOWNLOAD_URL..."
wget -q --show-progress $DOWNLOAD_URL -O postman.tar.gz

# Check if download was successful
if [ $? -ne 0 ]; then
    echo "Download failed. Please check your network connection and try again."
    exit 1
fi

# Extract the tarball
echo "Extracting Postman..."
tar -xvzf postman.tar.gz

# Move the extracted files to /opt/
echo "Moving Postman to /opt/"
sudo mv Postman /opt/

# Create a symbolic link for easier access
echo "Creating a symbolic link for Postman..."
sudo ln -s /opt/Postman/Postman /usr/local/bin/postman

# Create a desktop shortcut (optional)
echo "Creating a desktop shortcut for Postman..."
cat << EOF > ~/.local/share/applications/postman.desktop
[Desktop Entry]
Name=Postman
Comment=Postman API Testing
Exec=/opt/Postman/Postman
Icon=/opt/Postman/app/resources/app/icon.png
Terminal=false
Type=Application
Categories=Development;
EOF

# Clean up
echo "Cleaning up..."
rm -f postman.tar.gz

# Success message
echo "Postman has been successfully installed!"
echo "You can now launch it by typing 'postman' in the terminal or from your application menu."

