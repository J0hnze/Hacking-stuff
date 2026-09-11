#!/bin/bash

sudo cp /etc/apt/sources.list /etc/apt/sources.bak && sudo echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" >> /etc/apt/sources.list
sudo apt install -y kali-desktop-kde && sudo update-alternatives --config x-session-manager

