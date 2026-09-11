#!/bin/bash

echo "alias _venv_here='python3 -m venv .venv && source ./.venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt' " >> ~/.aliases 
echo "source ~/.aliases" >> ~/.zshrc
source ~/.zshrc