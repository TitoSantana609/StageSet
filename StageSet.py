#!/usr/bin/env python3
"""
Santana's Scanner - Enhanced Version with Subdomain Enumeration
A comprehensive network scanning tool with improved functionality
"""

import socket
import threading
import subprocess
import ipaddress
import sys
import time
import json
import requests
import os
from datetime import datetime
import urllib.parse

class SantanaScanner:
    def __init__(self):
        self.open_ports = []
        self.scan_results = {}
        self.subdomains = set()
        self.lock = threading.Lock()
        
    def validate_ip(self, target):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def validate_domain(self, domain):
        """Validate domain name format"""
        try:
            socket.getaddrinfo(domain, None)
            return True
        except socket.gaierror:
            return False
    
    def validate_port_range(self, start_port, end_port):
        """Validate port range"""
        if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
            return True
        return False
    
    def port_scan_tcp(self, target, port, timeout=1):
        """TCP port scanning with proper error handling"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    with self.lock:
                        self.open_ports.append(port)
                    try:
                        # Try to get banner
                        sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        service = self.get_service_name(port)
                    except:
                        banner = "Unable to retrieve banner"
                        service = "Unknown"
                    
                    with self.lock:
                        self.scan_results[port] = {
                            'service': service,
                            'banner': banner[:100]  # Limit banner length
                        }
                    return True
        except Exception as e:
            pass
        return False
    
    def port_scan_udp(self, target, port, timeout=1):
        """UDP port scanning (basic implementation)"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                # Send empty data to trigger response
                sock.sendto(b"", (target, port))
                sock.recvfrom(1024)
                with self.lock:
                    self.open_ports.append(port)
                    self.scan_results[port] = {
                        'service': self.get_service_name(port),
                        'banner': 'UDP service'
                    }
                return True
        except:
            pass
        return False
    
    def get_service_name(self, port):
        """Get common service name for port"""
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 115: 'SFTP', 135: 'RPC',
            139: 'NetBIOS', 143: 'IMAP', 194: 'IRC', 443: 'HTTPS',
            445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP',
            3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
        }
        return common_services.get(port, 'Unknown')
    
    def ping_sweep(self, network, timeout=1):
        """Perform ping sweep on a network range"""
        live_hosts = []
        
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            print(f"Invalid network range: {e}")
            return live_hosts
        
        print(f"Performing ping sweep on {network}...")
        
        def ping_host(ip):
            try:
                # Cross-platform ping command
                param = "-n" if sys.platform.lower().startswith("win") else "-c"
                command = ["ping", param, "1", "-W" if sys.platform.lower().startswith("win") else "-w", 
                          str(int(timeout * 1000)), str(ip)]
                
                result = subprocess.run(command, capture_output=True, text=True, timeout=timeout+2)
                
                if result.returncode == 0:
                    with self.lock:
                        live_hosts.append(str(ip))
                        print(f"  [+] {ip} is live")
            except:
                pass
        
        threads = []
        for ip in network_obj.hosts():
            thread = threading.Thread(target=ping_host, args=(ip,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
            
        return live_hosts
    
    def scan_ports(self, target, start_port=1, end_port=1000, scan_type='tcp', threads=100, timeout=1):
        """Main port scanning function"""
        if not self.validate_ip(target) and not self.validate_domain(target):
            print(f"Error: Invalid target: {target}")
            return
        
        if not self.validate_port_range(start_port, end_port):
            print("Error: Invalid port range")
            return
        
        print(f"Starting {scan_type.upper()} scan on {target}")
        print(f"Port range: {start_port}-{end_port}")
        print(f"Threads: {threads}")
        print("-" * 50)
        
        start_time = time.time()
        self.open_ports = []
        self.scan_results = {}
        
        scan_function = self.port_scan_tcp if scan_type.lower() == 'tcp' else self.port_scan_udp
        
        def scan_port(port):
            scan_function(target, port, timeout)
        
        # Create and manage threads
        thread_pool = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(port,))
            thread_pool.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(thread_pool) >= threads:
                for t in thread_pool:
                    t.join()
                thread_pool = []
        
        # Wait for remaining threads
        for thread in thread_pool:
            thread.join()
        
        end_time = time.time()
        self.display_results(target, start_time, end_time)
    
    def display_results(self, target, start_time, end_time):
        """Display scan results in a formatted way"""
        print("\n" + "="*60)
        print(f"SCAN RESULTS FOR: {target}")
        print("="*60)
        
        if not self.open_ports:
            print("No open ports found.")
            return
        
        print(f"{'PORT':<8} {'STATE':<6} {'SERVICE':<12} {'BANNER'}")
        print("-" * 60)
        
        for port in sorted(self.open_ports):
            service = self.scan_results[port]['service']
            banner = self.scan_results[port]['banner']
            print(f"{port:<8} {'open':<6} {service:<12} {banner}")
        
        print("-" * 60)
        print(f"Scan completed in {end_time - start_time:.2f} seconds")
        print(f"Found {len(self.open_ports)} open ports")
    
    def comprehensive_scan(self, target):
        """Perform a comprehensive scan with common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                       993, 995, 1723, 3306, 3389, 5900, 8080]
        
        print(f"Performing comprehensive scan on {target}...")
        print("Scanning common service ports...")
        
        start_time = time.time()
        self.open_ports = []
        self.scan_results = {}
        
        threads = []
        for port in common_ports:
            thread = threading.Thread(target=self.port_scan_tcp, args=(target, port, 2))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        self.display_results(target, start_time, end_time)

    # Subdomain Enumeration Methods
    
    def check_tool_installed(self, tool_name):
        """Check if a security tool is installed"""
        try:
            if tool_name == "amass":
                result = subprocess.run(["amass", "-version"], capture_output=True, text=True)
                return result.returncode == 0
            elif tool_name == "subfinder":
                result = subprocess.run(["subfinder", "-version"], capture_output=True, text=True)
                return result.returncode == 0
        except FileNotFoundError:
            return False
        return False

    def query_crtsh(self, domain):
        """Query crt.sh for subdomains"""
        print(f"Querying crt.sh for {domain}...")
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    common_name = entry.get('common_name', '')
                    if common_name and domain in common_name:
                        subdomains.add(common_name.lower())
                    
                    # Also check name_value field which often contains multiple subdomains
                    name_value = entry.get('name_value', '')
                    if name_value:
                        for name in name_value.split('\n'):
                            if domain in name.lower():
                                subdomains.add(name.lower().strip())
            
            print(f"  [+] crt.sh found {len(subdomains)} subdomains")
            return subdomains
            
        except Exception as e:
            print(f"  [-] Error querying crt.sh: {e}")
            return subdomains

    def run_amass(self, domain, intensity=1):
        """Run Amass for subdomain enumeration"""
        print(f"Running Amass on {domain}...")
        subdomains = set()
        
        if not self.check_tool_installed("amass"):
            print("  [-] Amass not installed. Skipping...")
            return subdomains
        
        try:
            # Basic amass scan
            command = [
                "amass", "enum", 
                "-d", domain,
                "-passive",
                "-o", f"amass_{domain}.txt"
            ]
            
            # Add intensity levels
            if intensity == 2:
                command.extend(["-active"])
            elif intensity == 3:
                command.extend(["-active", "-brute"])
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                # Read results from file
                try:
                    with open(f"amass_{domain}.txt", 'r') as f:
                        for line in f:
                            subdomain = line.strip().lower()
                            if subdomain and domain in subdomain:
                                subdomains.add(subdomain)
                    # Clean up temporary file
                    os.remove(f"amass_{domain}.txt")
                except FileNotFoundError:
                    # Parse from stdout if file not found
                    for line in result.stdout.split('\n'):
                        if domain in line.lower():
                            subdomains.add(line.strip().lower())
            
            print(f"  [+] Amass found {len(subdomains)} subdomains")
            return subdomains
            
        except subprocess.TimeoutExpired:
            print("  [-] Amass scan timed out")
            return subdomains
        except Exception as e:
            print(f"  [-] Error running Amass: {e}")
            return subdomains

    def run_subfinder(self, domain):
        """Run Subfinder for subdomain enumeration"""
        print(f"Running Subfinder on {domain}...")
        subdomains = set()
        
        if not self.check_tool_installed("subfinder"):
            print("  [-] Subfinder not installed. Skipping...")
            return subdomains
        
        try:
            command = [
                "subfinder",
                "-d", domain,
                "-o", f"subfinder_{domain}.txt"
            ]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Read results from file
                try:
                    with open(f"subfinder_{domain}.txt", 'r') as f:
                        for line in f:
                            subdomain = line.strip().lower()
                            if subdomain and domain in subdomain:
                                subdomains.add(subdomain)
                    # Clean up temporary file
                    os.remove(f"subfinder_{domain}.txt")
                except FileNotFoundError:
                    # Parse from stdout if file not found
                    for line in result.stdout.split('\n'):
                        if domain in line.lower():
                            subdomains.add(line.strip().lower())
            
            print(f"  [+] Subfinder found {len(subdomains)} subdomains")
            return subdomains
            
        except subprocess.TimeoutExpired:
            print("  [-] Subfinder scan timed out")
            return subdomains
        except Exception as e:
            print(f"  [-] Error running Subfinder: {e}")
            return subdomains

    def enumerate_subdomains(self, domain, methods=None, intensity=1):
        """
        Comprehensive subdomain enumeration
        
        Args:
            domain: Target domain
            methods: List of methods to use ['crtsh', 'amass', 'subfinder']
            intensity: Scan intensity (1-3)
        """
        if methods is None:
            methods = ['crtsh', 'amass', 'subfinder']
        
        if not self.validate_domain(domain):
            print(f"Error: Invalid domain: {domain}")
            return set()
        
        print(f"\nStarting subdomain enumeration for: {domain}")
        print("=" * 50)
        
        all_subdomains = set()
        
        # Run selected enumeration methods
        if 'crtsh' in methods:
            crtsh_subs = self.query_crtsh(domain)
            all_subdomains.update(crtsh_subs)
        
        if 'amass' in methods:
            amass_subs = self.run_amass(domain, intensity)
            all_subdomains.update(amass_subs)
        
        if 'subfinder' in methods:
            subfinder_subs = self.run_subfinder(domain)
            all_subdomains.update(subfinder_subs)
        
        # Remove duplicates and sort
        sorted_subdomains = sorted(all_subdomains)
        
        # Display results
        print("\n" + "=" * 50)
        print(f"SUBDOAMIN ENUMERATION RESULTS FOR: {domain}")
        print("=" * 50)
        
        for i, subdomain in enumerate(sorted_subdomains, 1):
            print(f"{i:3}. {subdomain}")
        
        print(f"\nTotal unique subdomains found: {len(sorted_subdomains)}")
        
        # Save to file
        filename = f"subdomains_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, 'w') as f:
                for subdomain in sorted_subdomains:
                    f.write(subdomain + '\n')
            print(f"Results saved to: {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")
        
        self.subdomains = set(sorted_subdomains)
        return self.subdomains

    def resolve_subdomains(self, subdomains=None):
        """Resolve subdomains to IP addresses"""
        if subdomains is None:
            subdomains = self.subdomains
        
        print(f"\nResolving {len(subdomains)} subdomains to IP addresses...")
        resolved = {}
        
        def resolve_subdomain(subdomain):
            try:
                ip = socket.gethostbyname(subdomain)
                with self.lock:
                    resolved[subdomain] = ip
                    print(f"  [+] {subdomain} -> {ip}")
            except socket.gaierror:
                with self.lock:
                    resolved[subdomain] = "Unable to resolve"
                    print(f"  [-] {subdomain} -> Unable to resolve")
        
        threads = []
        for subdomain in subdomains:
            thread = threading.Thread(target=resolve_subdomain, args=(subdomain,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 20:
                for t in threads:
                    t.join()
                threads = []
        
        for thread in threads:
            thread.join()
        
        return resolved

def main():
    """Main function with user interface"""
    scanner = SantanaScanner()
    
    print("Santana's Scanner - Enhanced Version with Subdomain Enumeration")
    print("=" * 60)
    
    while True:
        print("\nOptions:")
        print("1. TCP Port Scan")
        print("2. UDP Port Scan")
        print("3. Comprehensive Scan")
        print("4. Ping Sweep")
        print("5. Subdomain Enumeration")
        print("6. Resolve Subdomains")
        print("7. Full Reconnaissance (Subdomains + Port Scan)")
        print("8. Exit")
        
        choice = input("\nSelect option (1-8): ").strip()
        
        if choice == '1':
            target = input("Enter target IP or domain: ").strip()
            try:
                start_port = int(input("Start port (default 1): ") or 1)
                end_port = int(input("End port (default 1000): ") or 1000)
                threads = int(input("Threads (default 100): ") or 100)
                timeout = float(input("Timeout in seconds (default 1): ") or 1)
                
                scanner.scan_ports(target, start_port, end_port, 'tcp', threads, timeout)
            except ValueError as e:
                print(f"Invalid input: {e}")
        
        elif choice == '2':
            target = input("Enter target IP or domain: ").strip()
            try:
                start_port = int(input("Start port (default 1): ") or 1)
                end_port = int(input("End port (default 1000): ") or 1000)
                threads = int(input("Threads (default 50): ") or 50)
                timeout = float(input("Timeout in seconds (default 2): ") or 2)
                
                scanner.scan_ports(target, start_port, end_port, 'udp', threads, timeout)
            except ValueError as e:
                print(f"Invalid input: {e}")
        
        elif choice == '3':
            target = input("Enter target IP or domain: ").strip()
            scanner.comprehensive_scan(target)
        
        elif choice == '4':
            network = input("Enter network (e.g., 192.168.1.0/24): ").strip()
            timeout = float(input("Timeout in seconds (default 1): ") or 1)
            live_hosts = scanner.ping_sweep(network, timeout)
            print(f"\nFound {len(live_hosts)} live hosts")
        
        elif choice == '5':
            domain = input("Enter domain to enumerate (e.g., example.com): ").strip()
            print("\nEnumeration methods:")
            print("1. All methods (crt.sh + Amass + Subfinder)")
            print("2. crt.sh only (fast)")
            print("3. Amass only (comprehensive)")
            print("4. Subfinder only (fast)")
            
            method_choice = input("Select method (1-4, default 1): ").strip() or "1"
            
            methods_map = {
                "1": ['crtsh', 'amass', 'subfinder'],
                "2": ['crtsh'],
                "3": ['amass'],
                "4": ['subfinder']
            }
            
            methods = methods_map.get(method_choice, ['crtsh', 'amass', 'subfinder'])
            intensity = int(input("Scan intensity (1-3, default 1): ") or 1)
            
            scanner.enumerate_subdomains(domain, methods, intensity)
        
        elif choice == '6':
            if not scanner.subdomains:
                print("No subdomains found. Run subdomain enumeration first.")
                continue
            resolved = scanner.resolve_subdomains()
            print(f"\nResolved {len([ip for ip in resolved.values() if ip != 'Unable to resolve'])} subdomains")
        
        elif choice == '7':
            domain = input("Enter domain for full reconnaissance: ").strip()
            
            # Step 1: Subdomain enumeration
            subdomains = scanner.enumerate_subdomains(domain)
            
            if subdomains:
                # Step 2: Resolve subdomains
                resolved = scanner.resolve_subdomains(subdomains)
                
                # Step 3: Port scan on resolved IPs
                live_ips = set(ip for ip in resolved.values() if ip != "Unable to resolve")
                
                if live_ips:
                    print(f"\nStarting port scans on {len(live_ips)} resolved IPs...")
                    for ip in live_ips:
                        if scanner.validate_ip(ip):
                            print(f"\nScanning {ip}...")
                            scanner.comprehensive_scan(ip)
        
        elif choice == '8':
            print("Goodbye!")
            break
        
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
