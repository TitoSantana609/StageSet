# StageSet.py
This Python based tool will perform the following features: Nmap Scan, Ping Sweep, Subdomain Enumeration, and Full Recon (subdomain and port scans) This sets the stage for the show

Subdomain enumeration pulls from crt.sh, crt.name, Amass, and Subfinder. Live/dead status for discovered subdomains is checked with dnsx.

Installation Requirements:

# crt.sh and crt.name are queried over HTTP directly, no installation needed

# Install required tools (Kali Linux)
sudo apt update <br>
sudo apt install amass subfinder dnsx <br>
# Install required tools
go install github.com/lc/gau/v2/cmd/gau@latest <br>
go install github.com/tomnomnom/gf@latest <br>
go install github.com/s0md3v/uro@latest <br>


# Install Python packages
pip3 install requests beautifulsoup4

# Setup gf patterns
git clone https://github.com/tomnomnom/gf <br>
mkdir -p ~/.gf <br>
cp -r gf/examples/* ~/.gf/ <br>

# Install Python dependencies
pip3 install requests

# Or on other systems
# Download and install Amass: https://github.com/OWASP/Amass
# Download and install Subfinder: https://github.com/projectdiscovery/subfinder
# Download and install dnsx: https://github.com/projectdiscovery/dnsx

Usage Examples:


# Basic subdomain enumeration
python3 SantanaScanner.py
# Choose option 5, enter domain

# Full reconnaissance workflow
python3 SantanaScanner.py
# Choose option 7 for complete automation

# Command line usage for specific domains
echo "example.com" | python3 SantanaScanner.py

<br>
Coming Soon: Option to specify a specific endpoint to run the XSS scanner on.
