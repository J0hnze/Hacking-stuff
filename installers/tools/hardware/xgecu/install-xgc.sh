# Install Wine
echo "Installing Wine..."
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install -y wine64 wine32 git

# Verify Wine installation
wine --version

# Set proper permissions for Wine directory
echo "Setting correct permissions for Wine..."
sudo chmod -R 755 ~/.wine
sudo chown -R $USER:$USER ~/.wine

# Ensure home folder is accessible
echo "Ensuring home folder has correct permissions..."
sudo chmod 755 ~

# Remove and reinstall Wine if needed
echo "************************************"
echo "Do you want to reinstall Wine? (y/n)"
echo "************************************"

read reinstall
if [[ "$reinstall" == "y" ]]; then
    echo "Reinstalling Wine..."
    sudo apt remove --purge -y wine wine64 wine32
    sudo apt install -y wine64 wine32
fi

echo "******************************************************"
echo "** Make sure you add z as a drive at the location / **"
echo "******************************************************"

winecfg

# Create Xgecu directory
XGPRO_DIR=$HOME/Documents/Tools/Xgpro
mkdir -p "$XGPRO_DIR"
cd "$XGPRO_DIR"

# Download Xgecu Software Installer
echo "Downloading Xgpro Installer..."

wget -O xgpro_setup.rar "https://github.com/Kreeblah/XGecu_Software/raw/refs/heads/master/Xgpro/12/xgproV1278_Setup.rar"
# https://github.com/Kreeblah/XGecu_Software/raw/refs/heads/master/Xgpro/12/xgproV1288_setup.rar

# Install unrar if not installed
echo "Installing unrar..."
sudo apt install -y unrar

# Extract the installer
echo "Extracting Xgpro Installer..."
unrar x xgpro_setup.rar "$XGPRO_DIR/"

# Find and run the setup.exe
echo "Running Xgpro setup..."
SETUP_EXE=$(find "$XGPRO_DIR" -name "XgproV1278_Setup.exe" | head -n 1)
if [[ -f "$SETUP_EXE" ]]; then
    wine "$SETUP_EXE"
else
    echo "XgproV1278_Setup.exe not found!"
    exit 1
fi

# Install USB dependencies
echo "Installing USB dependencies..."
sudo apt install -y libusb-1.0-0 libusb-1.0-0-dev

# Check if the T48 is detected
echo "Checking if the T48 is detected..."
lsusb

# Create UDEV rule for USB access
echo "Creating UDEV rule for Xgecu T48..."
echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="7584", MODE="0666"' | sudo tee /etc/udev/rules.d/99-xgecu.rules

sudo wget -O /etc/udev/rules.d/60-minipro.rules https://raw.githubusercontent.com/radiomanV/TL866/refs/heads/master/udev/60-minipro.rules
sudo wget -O /etc/udev/rules.d/61-minipro-plugdev.rules https://raw.githubusercontent.com/radiomanV/TL866/refs/heads/master/udev/61-minipro-plugdev.rules
sudo wget -O /etc/udev/rules.d/61-minipro-uaccess.rules https://raw.githubusercontent.com/radiomanV/TL866/refs/heads/master/udev/61-minipro-uaccess.rules

# Reload UDEV rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Architecture support
sudo apt install libusb-1.0-0:i386 libudev1:i386
WINEPREFIX="$HOME/wine32" WINEARCH=win32 wine wineboot

# add setupapi.dll
echo "Downloading setupapi.dll..."
wget -O $XGPRO_DIR/setupapi.dll https://github.com/radiomanV/TL866/raw/refs/heads/master/wine/setupapi.dll

# Run Xgpro
echo "Running Xgpro..."
XGPRO_EXE=$(find "$XGPRO_DIR" -name "Xgpro.exe" | head -n 1)
if [[ -f "$XGPRO_EXE" ]]; then
    wine "$XGPRO_EXE"
else
    echo "Xgpro.exe not found!"
    exit 1
fi

echo "************************************"
echo "    The xgeku tool is located at:   "
echo $XGPRO_DIR
echo "************************************"
