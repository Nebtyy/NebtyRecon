#!/bin/bash

# Updating the system and installing the necessary utilities
echo "Updating the system and installing the necessary utilities..."
sudo apt-get update
sudo apt-get install -y curl jq git python3 python3-pip

# Install Go if it is not installed
if ! command -v go &> /dev/null; then
    echo "Install Go..."
    wget https://dl.google.com/go/go1.20.2.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.20.2.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    source ~/.profile
fi

# Installing Go utilities
echo "Installing Go utilities..."
go install github.com/projectdiscovery/subfinder/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/OWASP/Amass/v3/...@latest
go install github.com/lc/subzy@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Installing Python libraries from requirements.txt
echo "Installing Python libraries..."
pip install -r requirements.txt

# Installing SecretFinder
echo "Installing SecretFinder..."
git clone https://github.com/m4ll0k/SecretFinder.git ~/Downloads/secretfinder
pip install -r ~/Downloads/secretfinder/requirements.txt

echo "All dependencies installed successfully!"
