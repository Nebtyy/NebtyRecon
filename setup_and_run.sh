#!/bin/bash

# Updating the system and installing the necessary utilities
echo "Updating the system and installing the necessary utilities..."
sudo apt-get update
sudo apt-get install -y curl jq git python3 python3-pip wget linkchecker python3-venv xsltproc nmap dnsrecon

# Install Go if it is not installed
if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    wget https://dl.google.com/go/go1.20.2.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.20.2.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
    source ~/.profile
fi

# Ensure Go environment paths are set
export PATH=$PATH:/usr/local/go/bin
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.profile

# Installing Go utilities
echo "Installing Go utilities..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/owasp-amass/amass/v3/...@v3.23.3
go install -v github.com/PentestPad/subzy@latest
go install github.com/lc/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/michenriksen/aquatone@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/hakluke/hakrawler@latest

mkdir -p ./MyTools
cd MyTools
wget https://raw.githubusercontent.com/Haxxnet/nmap-bootstrap-xsl/main/nmap-bootstrap.xsl
# Installing Aquatone
mkdir Aquatone
cd Aquatone
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
cd ..

# Installing SecretFinder
echo "Installing SecretFinder..."
if [ ! -d "SecretFinder" ]; then
    git clone https://github.com/m4ll0k/SecretFinder.git
    cd SecretFinder
    pip install -r requirements.txt
    cd ..
else
    echo "SecretFinder already installed."
fi

# Installing Waymore
if [ ! -d "waymore" ]; then
    git clone https://github.com/xnl-h4ck3r/waymore.git
    cd waymore
    pip install -r requirements.txt
    cd ..
else
    echo "Waymore already installed."
fi

# Installing Sublist3r
if [ ! -d "Sublist3r" ]; then
    git clone https://github.com/aboul3la/Sublist3r.git
    cd Sublist3r
    pip install -r requirements.txt
    cd ..
else
    echo "Sublist3r already installed."
fi

# Installing Cloudrecon
if [ ! -d "cloudrecon" ]; then
    git clone https://github.com/0xSpidey/cloudrecon.git
    cd cloudrecon
    chmod +x main.sh
    cd ..
else
    echo "Cloudrecon already installed."
fi
# Ensuring all necessary Python libraries are installed
echo "Ensuring additional Python libraries are installed..."
pip install --upgrade pip
pip install beautifulsoup4 lxml html5lib selenium uro subprocess requests pytest

echo "All dependencies installed successfully!"
