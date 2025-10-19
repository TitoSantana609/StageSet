# StageSet.py
This Python based tool will perform the following features: Nmap Scan, Ping Sweep, Subdomain Enumeration, and Full Recon (subdomain and port scans) This sets the stage for the show
Installation Requirements:


# Install required tools (Kali Linux)
sudo apt update
sudo apt install amass subfinder
# Install required tools
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/gf@latest
go install github.com/s0md3v/uro@latest

# Install Python packages
pip3 install requests beautifulsoup4

# Setup gf patterns
git clone https://github.com/tomnomnom/gf
mkdir -p ~/.gf
cp -r gf/examples/* ~/.gf/

# Install Python dependencies
pip3 install requests

# Or on other systems
# Download and install Amass: https://github.com/OWASP/Amass
# Download and install Subfinder: https://github.com/projectdiscovery/subfinder

Usage Examples:


# Basic subdomain enumeration
python3 SantanaScanner.py
# Choose option 5, enter domain

# Full reconnaissance workflow
python3 SantanaScanner.py
# Choose option 7 for complete automation

# Command line usage for specific domains
echo "example.com" | python3 SantanaScanner.py
