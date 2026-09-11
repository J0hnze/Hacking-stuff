#! /bin/sh

VERSION="11.3.1_PUBLIC_20250219"

sudo apt-get install wget openjdk-21-jdk -y
wget -o pkgs/ghidra_$VERSION.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.1_build/ghidra_11.3.1_PUBLIC_20250219.zip

sudo mv ghidra_$VERSION.zip /opt/
cd /opt/
sudo unzip ghidra_$VERSION.zip
sudo mv ghidra_$VERSION ghidra

cd /opt/ghidra
./ghidraRun

echo "[Desktop Entry]
Name=Ghidra
Comment=Software Reverse Engineering Suite
Exec=/opt/ghidra/ghidraRun
Icon=/opt/ghidra/docs/images/GHIDRA_1.png
Terminal=false
Type=Application
Categories=Development;Security;" >> ~/.local/share/applications/ghidra.desktop

sudo chmod +x ~/.local/share/applications/ghidra.desktop

