#!/usr/bin/env python3
"""
Santana's Scanner - Enhanced Version with Advanced XSS Detection
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
import random
import string
from datetime import datetime
import urllib.parse
import re
from bs4 import BeautifulSoup
import tempfile
import glob

class SantanaScanner:
    def __init__(self):
        self.open_ports = []
        self.scan_results = {}
        self.subdomains = set()
        self.xss_findings = []
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

    # Advanced XSS Detection with GAU and gf Integration
    
    def check_tool_installed(self, tool_name):
        """Check if a security tool is installed"""
        try:
            if tool_name == "amass":
                result = subprocess.run(["amass", "-version"], capture_output=True, text=True)
                return result.returncode == 0
            elif tool_name == "subfinder":
                result = subprocess.run(["subfinder", "-version"], capture_output=True, text=True)
                return result.returncode == 0
            elif tool_name == "gau":
                result = subprocess.run(["gau", "-version"], capture_output=True, text=True)
                return result.returncode == 0
            elif tool_name == "gf":
                result = subprocess.run(["gf", "-version"], capture_output=True, text=True)
                return result.returncode == 0
            elif tool_name == "uro":
                result = subprocess.run(["uro", "-h"], capture_output=True, text=True)
                return result.returncode == 0
        except FileNotFoundError:
            return False
        return False

    def run_gau_for_subdomain(self, subdomain, output_file):
        """Run GAU to get all URLs for a subdomain"""
        print(f"    [+] Running GAU for {subdomain}")
        start_time = time.time()
        
        try:
            command = ["gau", subdomain, "--o", output_file]
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            
            end_time = time.time()
            
            if result.returncode == 0:
                # Count lines in output file
                try:
                    with open(output_file, 'r') as f:
                        line_count = sum(1 for _ in f)
                    print(f"    [+] GAU found {line_count} URLs for {subdomain} in {end_time - start_time:.2f}s")
                    return True
                except:
                    print(f"    [-] No URLs found for {subdomain}")
            else:
                print(f"    [-] GAU failed for {subdomain}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"    [-] GAU timed out for {subdomain}")
        except Exception as e:
            print(f"    [-] Error running GAU for {subdomain}: {e}")
        
        return False

    def run_gf_xss_filter(self, input_file, output_file):
        """Run gf XSS filter on URLs"""
        print(f"    [+] Running gf XSS filter")
        start_time = time.time()
        
        try:
            command = ["gf", "xss", input_file]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            
            end_time = time.time()
            
            if result.returncode == 0 and result.stdout.strip():
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                
                line_count = len(result.stdout.strip().split('\n'))
                print(f"    [+] gf XSS found {line_count} potential XSS URLs in {end_time - start_time:.2f}s")
                return True
            else:
                print(f"    [-] No XSS patterns found")
                
        except subprocess.TimeoutExpired:
            print(f"    [-] gf XSS filter timed out")
        except Exception as e:
            print(f"    [-] Error running gf XSS filter: {e}")
        
        return False

    def run_uro_filter(self, input_file, output_file):
        """Run URO to filter and normalize URLs"""
        print(f"    [+] Running URO filter")
        start_time = time.time()
        
        try:
            command = ["uro", "-i", input_file]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            
            end_time = time.time()
            
            if result.returncode == 0 and result.stdout.strip():
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                
                line_count = len(result.stdout.strip().split('\n'))
                print(f"    [+] URO processed {line_count} URLs in {end_time - start_time:.2f}s")
                return True
            else:
                print(f"    [-] URO found no unique URLs")
                
        except subprocess.TimeoutExpired:
            print(f"    [-] URO filter timed out")
        except Exception as e:
            print(f"    [-] Error running URO filter: {e}")
        
        return False

    def extract_parameters_with_sed(self, input_file, output_file):
        """Extract parameters using sed-like functionality"""
        print(f"    [+] Extracting parameters with sed")
        start_time = time.time()
        
        try:
            with open(input_file, 'r') as f:
                urls = f.readlines()
            
            parameters = set()
            for url in urls:
                url = url.strip()
                if '?' in url and '=' in url:
                    # Extract parameters using regex (sed 's/=.*/=/' equivalent)
                    param_pattern = r'(\?|&)([^=]+)=[^&]*'
                    matches = re.findall(param_pattern, url)
                    for match in matches:
                        param_name = match[1]
                        parameters.add(f"{param_name}=")
            
            with open(output_file, 'w') as f:
                for param in sorted(parameters):
                    f.write(param + '\n')
            
            end_time = time.time()
            print(f"    [+] Extracted {len(parameters)} unique parameters in {end_time - start_time:.2f}s")
            return len(parameters) > 0
            
        except Exception as e:
            print(f"    [-] Error extracting parameters: {e}")
            return False

    def advanced_xss_scan_subdomains(self, subdomains, max_subdomains=10):
        """Advanced XSS scan using GAU, gf, and URO for subdomains"""
        print(f"\n🚀 Starting Advanced XSS Scan for {len(subdomains)} subdomains")
        print("=" * 70)
        
        overall_start = time.time()
        results = {}
        tools_status = self.check_required_tools()
        
        if not all(tools_status.values()):
            print("❌ Missing required tools:")
            for tool, available in tools_status.items():
                if not available:
                    print(f"   - {tool}")
            print("Please install missing tools and try again.")
            return results
        
        print("✅ All required tools are available")
        
        # Limit number of subdomains to process
        subdomains_to_process = list(subdomains)[:max_subdomains]
        
        print(f"📊 Processing {len(subdomains_to_process)} subdomains")
        
        for i, subdomain in enumerate(subdomains_to_process, 1):
            subdomain_start = time.time()
            print(f"\n🔍 [{i}/{len(subdomains_to_process)}] Processing: {subdomain}")
            
            # Create directory for this subdomain
            domain_dir = f"xss_scan_{subdomain.replace('.', '_')}_{datetime.now().strftime('%H%M%S')}"
            os.makedirs(domain_dir, exist_ok=True)
            
            subdomain_results = {
                'directory': domain_dir,
                'gau_urls': 0,
                'gf_xss_urls': 0,
                'uro_urls': 0,
                'parameters_found': 0,
                'vulnerabilities': []
            }
            
            # Step 1: Run GAU
            gau_file = os.path.join(domain_dir, "gau_urls.txt")
            if self.run_gau_for_subdomain(subdomain, gau_file):
                subdomain_results['gau_urls'] = self.count_file_lines(gau_file)
            
            # Step 2: Run gf XSS filter
            gf_xss_file = os.path.join(domain_dir, "gf_xss_urls.txt")
            if self.run_gf_xss_filter(gau_file, gf_xss_file):
                subdomain_results['gf_xss_urls'] = self.count_file_lines(gf_xss_file)
            
            # Step 3: Run URO filter
            uro_file = os.path.join(domain_dir, "uro_urls.txt")
            if self.run_uro_filter(gf_xss_file, uro_file):
                subdomain_results['uro_urls'] = self.count_file_lines(uro_file)
            
            # Step 4: Extract parameters
            params_file = os.path.join(domain_dir, "parameters.txt")
            if self.extract_parameters_with_sed(uro_file, params_file):
                subdomain_results['parameters_found'] = self.count_file_lines(params_file)
            
            # Step 5: Test for XSS vulnerabilities
            if subdomain_results['uro_urls'] > 0:
                print(f"    [+] Testing {subdomain_results['uro_urls']} URLs for XSS vulnerabilities")
                vulnerabilities = self.test_urls_for_xss(uro_file, subdomain)
                subdomain_results['vulnerabilities'] = vulnerabilities
            
            subdomain_end = time.time()
            subdomain_results['processing_time'] = subdomain_end - subdomain_start
            
            print(f"    ✅ Completed {subdomain} in {subdomain_end - subdomain_start:.2f}s")
            results[subdomain] = subdomain_results
        
        overall_end = time.time()
        self.display_advanced_xss_results(results, overall_end - overall_start)
        return results

    def count_file_lines(self, filename):
        """Count lines in a file"""
        try:
            with open(filename, 'r') as f:
                return sum(1 for _ in f)
        except:
            return 0

    def check_required_tools(self):
        """Check if all required tools are installed"""
        tools = {
            'gau': self.check_tool_installed('gau'),
            'gf': self.check_tool_installed('gf'),
            'uro': self.check_tool_installed('uro')
        }
        return tools

    def test_urls_for_xss(self, urls_file, subdomain):
        """Test URLs from file for XSS vulnerabilities"""
        vulnerabilities = []
        try:
            with open(urls_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            print(f"    [+] Testing {len(urls)} URLs for XSS")
            
            for i, url in enumerate(urls[:20]):  # Limit to first 20 URLs for performance
                print(f"      Testing URL {i+1}/{min(len(urls), 20)}: {url[:80]}...")
                url_vulnerabilities = self.scan_for_xss(url)
                vulnerabilities.extend(url_vulnerabilities)
                
        except Exception as e:
            print(f"    [-] Error testing URLs: {e}")
        
        return vulnerabilities

    def display_advanced_xss_results(self, results, total_time):
        """Display advanced XSS scan results"""
        print(f"\n{'='*80}")
        print("🎯 ADVANCED XSS SCAN RESULTS")
        print(f"{'='*80}")
        
        total_urls = 0
        total_xss_urls = 0
        total_parameters = 0
        total_vulnerabilities = 0
        
        for subdomain, data in results.items():
            print(f"\n📁 {subdomain}")
            print(f"   📊 URLs found (GAU): {data['gau_urls']}")
            print(f"   🎯 XSS patterns (gf): {data['gf_xss_urls']}")
            print(f"   🔧 Unique URLs (URO): {data['uro_urls']}")
            print(f"   ⚙️  Parameters found: {data['parameters_found']}")
            print(f"   🚨 Vulnerabilities: {len(data['vulnerabilities'])}")
            print(f"   ⏱️  Processing time: {data['processing_time']:.2f}s")
            print(f"   💾 Output directory: {data['directory']}")
            
            total_urls += data['gau_urls']
            total_xss_urls += data['gf_xss_urls']
            total_parameters += data['parameters_found']
            total_vulnerabilities += len(data['vulnerabilities'])
        
        print(f"\n{'='*80}")
        print("📈 SUMMARY")
        print(f"{'='*80}")
        print(f"Total Subdomains Processed: {len(results)}")
        print(f"Total URLs Found: {total_urls}")
        print(f"Total XSS Pattern URLs: {total_xss_urls}")
        print(f"Total Unique Parameters: {total_parameters}")
        print(f"Total Vulnerabilities Found: {total_vulnerabilities}")
        print(f"Total Scan Time: {total_time:.2f} seconds")
        print(f"{'='*80}")
        
        # Save overall results
        self.save_advanced_results(results, total_time)

    def save_advanced_results(self, results, total_time):
        """Save advanced scan results to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"advanced_xss_scan_{timestamp}.json"
        
        try:
            summary = {
                'scan_timestamp': datetime.now().isoformat(),
                'total_scan_time_seconds': total_time,
                'subdomains_processed': len(results),
                'results': results
            }
            
            with open(filename, 'w') as f:
                json.dump(summary, f, indent=2)
            
            print(f"📄 Full results saved to: {filename}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")

    # Existing XSS detection methods (keep all previous XSS methods)
    def generate_xss_payloads(self):
        """Generate various XSS test payloads"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "#<script>alert('XSS')</script>",
            "?test=<script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<IMG SRC=javascript:alert('XSS')>",
            "jaVasCript:/*-/*`/*\`/*'/*\"/* */(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e"
        ]
        return payloads

    def detect_input_vectors(self, url, html_content):
        """Detect potential input vectors in HTML forms and URLs"""
        vectors = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find forms
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()
            
            inputs = form.find_all('input')
            for input_field in inputs:
                input_name = input_field.get('name', '')
                if input_name:
                    vectors.append({
                        'type': 'form',
                        'method': form_method,
                        'action': form_action,
                        'parameter': input_name,
                        'url': url
                    })
        
        # Find URL parameters
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        for param in query_params:
            vectors.append({
                'type': 'url',
                'method': 'get',
                'action': parsed_url.path,
                'parameter': param,
                'url': url
            })
        
        return vectors

    def test_xss_vector(self, vector, payload):
        """Test a specific vector with XSS payload"""
        try:
            if vector['type'] == 'form':
                data = {}
                data[vector['parameter']] = payload
                
                target_url = vector['url']
                if vector['action']:
                    if vector['action'].startswith('http'):
                        target_url = vector['action']
                    else:
                        base_url = urllib.parse.urlparse(vector['url'])
                        target_url = f"{base_url.scheme}://{base_url.netloc}{vector['action']}"
                
                if vector['method'] == 'post':
                    response = requests.post(target_url, data=data, timeout=10, verify=False)
                else:
                    response = requests.get(target_url, params=data, timeout=10, verify=False)
                
                return response
                
            elif vector['type'] == 'url':
                parsed_url = urllib.parse.urlparse(vector['url'])
                query_params = urllib.parse.parse_qs(parsed_url.query)
                query_params[vector['parameter']] = payload
                
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                response = requests.get(new_url, timeout=10, verify=False)
                return response
                
        except Exception as e:
            print(f"  [-] Error testing vector: {e}")
        
        return None

    def check_payload_reflection(self, response, payload):
        """Check if payload is reflected in response"""
        try:
            if payload in response.text:
                return True
            
            encoded_payload = urllib.parse.quote(payload)
            if encoded_payload in response.text:
                return True
            
            script_patterns = [r'<script[^>]*>', r'on\w+=', r'javascript:']
            for pattern in script_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True
                    
        except Exception as e:
            print(f"  [-] Error checking reflection: {e}")
        
        return False

    def scan_for_xss(self, url, depth=1, timeout=10):
        """Main XSS scanning function"""
        if not url.startswith('http'):
            url = 'http://' + url
        
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            response = session.get(url, timeout=timeout, verify=False)
            if response.status_code != 200:
                return []
            
            vectors = self.detect_input_vectors(url, response.text)
            if not vectors:
                return []
            
            payloads = self.generate_xss_payloads()
            vulnerabilities = []
            
            for vector in vectors:
                for payload in payloads:
                    response = self.test_xss_vector(vector, payload)
                    if response and self.check_payload_reflection(response, payload):
                        vulnerability = {
                            'url': url,
                            'vector': vector,
                            'payload': payload,
                            'confidence': 'medium',
                            'type': 'Reflected XSS'
                        }
                        vulnerabilities.append(vulnerability)
                        break
            
            return vulnerabilities
            
        except Exception as e:
            return []

    def display_xss_results(self, vulnerabilities):
        """Display XSS scan results"""
        if not vulnerabilities:
            print("\nNo XSS vulnerabilities found.")
            return
        
        print("\n" + "=" * 80)
        print("XSS VULNERABILITY REPORT")
        print("=" * 80)
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n{i}. VULNERABILITY FOUND:")
            print(f"   Type: {vuln['type']}")
            print(f"   URL: {vuln['url']}")
            print(f"   Vector Type: {vuln['vector']['type']}")
            print(f"   Parameter: {vuln['vector']['parameter']}")
            print(f"   Payload: {vuln['payload'][:100]}...")
            print(f"   Confidence: {vuln['confidence']}")
            print("-" * 80)
        
        print(f"\nTotal XSS vulnerabilities found: {len(vulnerabilities)}")

    # Existing subdomain enumeration methods
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
            command = ["amass", "enum", "-d", domain, "-passive", "-o", f"amass_{domain}.txt"]
            
            if intensity == 2:
                command.extend(["-active"])
            elif intensity == 3:
                command.extend(["-active", "-brute"])
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                try:
                    with open(f"amass_{domain}.txt", 'r') as f:
                        for line in f:
                            subdomain = line.strip().lower()
                            if subdomain and domain in subdomain:
                                subdomains.add(subdomain)
                    os.remove(f"amass_{domain}.txt")
                except FileNotFoundError:
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
            command = ["subfinder", "-d", domain, "-o", f"subfinder_{domain}.txt"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                try:
                    with open(f"subfinder_{domain}.txt", 'r') as f:
                        for line in f:
                            subdomain = line.strip().lower()
                            if subdomain and domain in subdomain:
                                subdomains.add(subdomain)
                    os.remove(f"subfinder_{domain}.txt")
                except FileNotFoundError:
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
        """Comprehensive subdomain enumeration"""
        if methods is None:
            methods = ['crtsh', 'amass', 'subfinder']
        
        if not self.validate_domain(domain):
            print(f"Error: Invalid domain: {domain}")
            return set()
        
        print(f"\nStarting subdomain enumeration for: {domain}")
        print("=" * 50)
        
        all_subdomains = set()
        
        if 'crtsh' in methods:
            crtsh_subs = self.query_crtsh(domain)
            all_subdomains.update(crtsh_subs)
        
        if 'amass' in methods:
            amass_subs = self.run_amass(domain, intensity)
            all_subdomains.update(amass_subs)
        
        if 'subfinder' in methods:
            subfinder_subs = self.run_subfinder(domain)
            all_subdomains.update(subfinder_subs)
        
        sorted_subdomains = sorted(all_subdomains)
        
        print("\n" + "=" * 50)
        print(f"SUBDOAMIN ENUMERATION RESULTS FOR: {domain}")
        print("=" * 50)
        
        for i, subdomain in enumerate(sorted_subdomains, 1):
            print(f"{i:3}. {subdomain}")
        
        print(f"\nTotal unique subdomains found: {len(sorted_subdomains)}")
        
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

def main():
    """Main function with user interface"""
    scanner = SantanaScanner()
    
    print("Santana's Scanner - Enhanced Version with Advanced XSS Detection")
    print("=" * 70)
    
    while True:
        print("\nOptions:")
        print("1. TCP Port Scan")
        print("2. UDP Port Scan")
        print("3. Comprehensive Scan")
        print("4. Ping Sweep")
        print("5. Subdomain Enumeration")
        print("6. XSS Scan (Single URL)")
        print("7. Advanced XSS Scan (Subdomains + GAU + gf + URO)")
        print("8. Full Reconnaissance (Complete Workflow)")
        print("9. Exit")
        
        choice = input("\nSelect option (1-9): ").strip()
        
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
            url = input("Enter URL to scan for XSS (e.g., http://example.com/search.php): ").strip()
            vulnerabilities = scanner.scan_for_xss(url)
            scanner.display_xss_results(vulnerabilities)
        
        elif choice == '7':
            if not scanner.subdomains:
                domain = input("Enter domain to enumerate first (e.g., example.com): ").strip()
                scanner.enumerate_subdomains(domain)
            
            if scanner.subdomains:
                max_subdomains = int(input("Max subdomains to process (default 5): ") or 5)
                scanner.advanced_xss_scan_subdomains(scanner.subdomains, max_subdomains)
        
        elif choice == '8':
            domain = input("Enter domain for full reconnaissance: ").strip()
            
            # Step 1: Subdomain enumeration
            print("\n" + "="*60)
            print("STEP 1: SUBDOMAIN ENUMERATION")
            print("="*60)
            subdomains = scanner.enumerate_subdomains(domain)
            
            if subdomains:
                # Step 2: Advanced XSS Scan
                print("\n" + "="*60)
                print("STEP 2: ADVANCED XSS SCAN")
                print("="*60)
                max_subdomains = int(input("Max subdomains for XSS scan (default 3): ") or 3)
                scanner.advanced_xss_scan_subdomains(subdomains, max_subdomains)
                
                # Step 3: Port scanning on discovered subdomains
                print("\n" + "="*60)
                print("STEP 3: PORT SCANNING")
                print("="*60)
                for subdomain in list(subdomains)[:2]:  # Limit to first 2
                    if scanner.validate_domain(subdomain):
                        print(f"\nPort scanning: {subdomain}")
                        scanner.comprehensive_scan(subdomain)
        
        elif choice == '9':
            print("Goodbye!")
            break
        
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    try:
        # Install required packages if not present
        try:
            import requests
            from bs4 import BeautifulSoup
        except ImportError:
            print("Installing required packages...")
            subprocess.run([sys.executable, "-m", "pip", "install", "requests", "beautifulsoup4"])
            import requests
            from bs4 import BeautifulSoup
        
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
