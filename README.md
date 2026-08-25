# StageSet.py
This Python based tool will perform the following features: Nmap Scan, Ping Sweep, Subdomain Enumeration, Directory Brute Forcing, and Full Recon (subdomain and port scans) This sets the stage for the show

Subdomain enumeration pulls from crt.sh, crt.name, Amass, and Subfinder. Live/dead status for discovered subdomains is checked with dnsx.

Directory brute forcing runs dirb and ffuf against the same target using a shared SecLists wordlist (raft-medium-directories.txt by default), combines and dedupes the paths both tools find, and lets you filter the combined results by status code and content length (handy for filtering out soft-404 pages).

A configurable HTTP proxy lets you route traffic through Burp Suite (or any intercepting proxy) so you can inspect requests as they go out. It covers requests-based traffic (crt.sh/crt.name queries, XSS payload testing) plus dirb, ffuf, and subfinder via their native proxy flags. gau, amass, and dnsx have no usable proxy path for this and will bypass it (the tool warns you when that happens).

Installation Requirements:

# crt.sh and crt.name are queried over HTTP directly, no installation needed

# Install required tools (Kali Linux)
sudo apt update <br>
sudo apt install amass subfinder dnsx dirb ffuf seclists <br>
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
python3 StageSet.py
# Choose option 5, enter domain

# Full reconnaissance workflow
python3 StageSet.py
# Choose option 9 for complete automation

# Directory brute forcing (dirb + ffuf, combined results)
python3 StageSet.py
# Choose option 10, enter target URL, pick a wordlist, optionally filter
# by status code and/or content length

# Route traffic through Burp Suite
python3 StageSet.py
# Choose option 11, enable the proxy (defaults to http://127.0.0.1:8080),
# then run any scan as normal to see the requests in Burp

# Command line usage for specific domains
echo "example.com" | python3 StageSet.py

<br>
Coming Soon: Option to specify a specific endpoint to run the XSS scanner on.
