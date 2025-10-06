#!/usr/bin/env python3
"""
SAYN - Subdomain Analysis & discovery Yielding Network intelligence
Advanced Asynchronous Subdomain Enumeration and Analysis Tool

Author: M.Nurlan
Email: nurlanmammadli2@gmail.com
LinkedIn: www.linkedin.com/in/nurlan-məmmədli-b6a55b308
"""

import argparse
import asyncio
import socket
import aiohttp
import subprocess
import logging
import json
import csv
import re
import ssl
import time
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Tuple, Optional, Set
from pathlib import Path

try:
    from colorama import Fore, Style, init
    from tqdm import tqdm
    import dns.resolver
    import dns.zone
    import dns.query
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install aiohttp colorama tqdm dnspython beautifulsoup4 requests")
    exit(1)

init(autoreset=True)

# ==========================================
# CONSTANTS & CONFIGURATION
# ==========================================
VERSION = "2.0.0"
COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888]
COMMON_TECH_SIGNATURES = {
    'WordPress': ['wp-content', 'wp-includes'],
    'Joomla': ['/administrator/', 'Joomla!'],
    'Drupal': ['Drupal', '/sites/default/'],
    'Shopify': ['cdn.shopify.com', 'Shopify'],
    'Node.js': ['X-Powered-By: Express'],
    'Apache': ['Apache/', 'Server: Apache'],
    'Nginx': ['nginx/', 'Server: nginx'],
    'IIS': ['Server: Microsoft-IIS'],
    'PHP': ['X-Powered-By: PHP'],
}

TAKEOVER_SIGNATURES = {
    's3.amazonaws.com': 'AWS S3',
    'github.io': 'GitHub Pages',
    'herokuapp.com': 'Heroku',
    'azurewebsites.net': 'Azure',
    'shopify.com': 'Shopify',
    'tumblr.com': 'Tumblr',
    'wordpress.com': 'WordPress',
}

# ==========================================
# BANNER & DISPLAY
# ==========================================
def print_banner():
    """Display the SAYN banner"""
    banner = f"""{Fore.CYAN}
  ____    _    __   ___   _ 
 / ___|  / \   \ \ / / \ | |
 \___ \ / _ \   \ V /|  \| |
  ___) / ___ \   | | | |\  |
 |____/_/   \_\  |_| |_| \_|
{Style.RESET_ALL}
{Fore.GREEN}[+] SAYN v{VERSION} - Advanced Subdomain Discovery Tool{Style.RESET_ALL}
{Fore.YELLOW}[+] Powered by M.Nurlan{Style.RESET_ALL}
{Fore.BLUE}[+] Email: nurlanmammadli2@gmail.com{Style.RESET_ALL}
{Fore.MAGENTA}[+] LinkedIn: www.linkedin.com/in/nurlan-məmmədli-b6a55b308{Style.RESET_ALL}
{'=' * 60}
"""
    print(banner)

# ==========================================
# LOGGING SETUP
# ==========================================
def setup_logging(verbose: bool = False, quiet: bool = False):
    """Configure logging based on verbosity"""
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    return logging.getLogger("SAYN")

# ==========================================
# DNS RESOLUTION & ZONE TRANSFER
# ==========================================
class DNSResolver:
    def __init__(self, dns_server: Optional[str] = None, retries: int = 2):
        self.resolver = dns.resolver.Resolver()
        if dns_server:
            self.resolver.nameservers = [dns_server]
        self.retries = retries
    
    async def resolve_ip(self, subdomain: str, loop) -> Optional[str]:
        """Resolve subdomain to IP address"""
        for attempt in range(self.retries):
            try:
                info = await loop.getaddrinfo(subdomain, None)
                return info[0][4][0]
            except Exception:
                if attempt == self.retries - 1:
                    return None
                await asyncio.sleep(0.3)
        return None
    
    def try_zone_transfer(self, domain: str, logger) -> List[str]:
        """Attempt DNS zone transfer (AXFR)"""
        subdomains = []
        try:
            ns_records = self.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_name = str(ns.target).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_name, domain, timeout=5))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{domain}" if name != '@' else domain
                        subdomains.append(subdomain)
                    logger.info(f"{Fore.GREEN}[AXFR] Successful zone transfer from {ns_name}{Style.RESET_ALL}")
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"Zone transfer failed: {e}")
        return subdomains

# ==========================================
# CERTIFICATE TRANSPARENCY
# ==========================================
async def fetch_crtsh(domain: str, http_timeout: int, logger) -> Set[str]:
    """Fetch subdomains from crt.sh"""
    logger.info(f"Searching Certificate Transparency logs for {domain}...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subs = set()
    
    timeout = aiohttp.ClientTimeout(total=http_timeout)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    logger.warning(f"crt.sh returned HTTP {resp.status}")
                    return subs
                
                data = await resp.json()
                for entry in data:
                    names = entry.get("name_value", "")
                    for sub in names.split("\n"):
                        sub = sub.strip().lower()
                        if sub and sub.endswith(domain) and '*' not in sub:
                            subs.add(sub)
                
                logger.info(f"{Fore.GREEN}Found {len(subs)} subdomains from crt.sh{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"Error fetching crt.sh: {e}")
    
    return subs

# ==========================================
# HTTP PROBING & TECHNOLOGY DETECTION
# ==========================================
class HTTPProber:
    def __init__(self, timeout: int = 5, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "SAYN/2.0 (Security Scanner)"
    
    async def probe_http(self, subdomain: str) -> Dict:
        """Probe HTTP/HTTPS and detect technologies"""
        result = {
            'http_status': None,
            'https_status': None,
            'technologies': [],
            'server': None,
            'title': None,
            'redirect': None
        }
        
        headers = {'User-Agent': self.user_agent}
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            for protocol in ['https', 'http']:
                url = f"{protocol}://{subdomain}"
                try:
                    async with session.get(url, allow_redirects=True, ssl=False) as resp:
                        status = resp.status
                        content = await resp.text()
                        
                        if protocol == 'https':
                            result['https_status'] = status
                        else:
                            result['http_status'] = status
                        
                        result['server'] = resp.headers.get('Server', 'Unknown')
                        
                        if content:
                            soup = BeautifulSoup(content, 'html.parser')
                            title_tag = soup.find('title')
                            if title_tag:
                                result['title'] = title_tag.get_text().strip()[:100]
                        
                        result['technologies'] = self.detect_technologies(resp.headers, content)
                        
                        if str(resp.url) != url:
                            result['redirect'] = str(resp.url)
                        
                        break  
                        
                except Exception:
                    continue
        
        return result
    
    def detect_technologies(self, headers: dict, content: str) -> List[str]:
        """Detect web technologies from headers and content"""
        techs = []
        
        for tech, signatures in COMMON_TECH_SIGNATURES.items():
            for sig in signatures:
                if any(sig.lower() in str(v).lower() for v in headers.values()):
                    techs.append(tech)
                    break
        
        if content:
            for tech, signatures in COMMON_TECH_SIGNATURES.items():
                if tech not in techs:
                    for sig in signatures:
                        if sig.lower() in content.lower():
                            techs.append(tech)
                            break
        
        return list(set(techs))

# ==========================================
# PORT SCANNER
# ==========================================
async def scan_ports(subdomain: str, ip: str, ports: List[int] = COMMON_PORTS) -> List[int]:
    """Scan common ports on subdomain"""
    open_ports = []
    
    for port in ports:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=2
            )
            open_ports.append(port)
            writer.close()
            await writer.wait_closed()
        except:
            continue
    
    return open_ports

# ==========================================
# SUBDOMAIN TAKEOVER DETECTION
# ==========================================
async def check_takeover(subdomain: str, logger) -> Optional[str]:
    """Check for potential subdomain takeover vulnerability"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        try:
            cname_records = resolver.resolve(subdomain, 'CNAME')
            for cname in cname_records:
                cname_target = str(cname.target).lower()
                
                for signature, service in TAKEOVER_SIGNATURES.items():
                    if signature in cname_target:
                        try:
                            async with aiohttp.ClientSession() as session:
                                async with session.get(f"http://{subdomain}", timeout=aiohttp.ClientTimeout(total=3)) as resp:
                                    content = await resp.text()
                                    error_msgs = ['not found', 'no such app', 'is not configured', 'NoSuchBucket']
                                    if any(msg.lower() in content.lower() for msg in error_msgs):
                                        return service
                        except:
                            pass
        except dns.resolver.NoAnswer:
            pass
    except Exception:
        pass
    
    return None

# ==========================================
# MAIN SCANNER CLASS
# ==========================================
class SubdomainScanner:
    def __init__(self, args, logger):
        self.args = args
        self.logger = logger
        self.dns_resolver = DNSResolver(args.dns_server, args.retries)
        self.http_prober = HTTPProber(args.timeout, args.user_agent)
        self.results = []
        self.stats = defaultdict(int)
        self.start_time = time.time()
    
    async def resolve_list(self, subdomains: List[str], label: str = "Resolving") -> List[Tuple]:
        """Resolve list of subdomains concurrently"""
        semaphore = asyncio.Semaphore(self.args.concurrency)
        loop = asyncio.get_event_loop()
        
        async def sem_resolve(sub):
            async with semaphore:
                if self.args.delay > 0:
                    await asyncio.sleep(self.args.delay / 1000)
                ip = await self.dns_resolver.resolve_ip(sub, loop)
                return (sub, ip)
        
        tasks = [asyncio.create_task(sem_resolve(s)) for s in subdomains]
        results = []
        
        if not self.args.quiet:
            for fut in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=label, unit="sub"):
                results.append(await fut)
        else:
            results = await asyncio.gather(*tasks)
        
        return results
    
    async def analyze_subdomain(self, subdomain: str, ip: str) -> Dict:
        """Perform comprehensive analysis on a subdomain"""
        result = {
            'subdomain': subdomain,
            'ip': ip,
            'timestamp': datetime.now().isoformat()
        }
        
        if self.args.probe:
            http_info = await self.http_prober.probe_http(subdomain)
            result.update(http_info)
        
        if self.args.ports and ip:
            open_ports = await scan_ports(subdomain, ip)
            result['open_ports'] = open_ports
        
        if self.args.takeover:
            takeover = await check_takeover(subdomain, self.logger)
            result['takeover_risk'] = takeover
        
        return result
    
    async def run_crtsh(self, domain: str) -> List[str]:
        """Run crt.sh enumeration"""
        subs = await fetch_crtsh(domain, self.args.timeout, self.logger)
        return list(subs)
    
    async def run_bruteforce(self, domain: str, wordlist_path: str) -> List[str]:
        """Run wordlist-based brute force"""
        try:
            with open(wordlist_path, 'r') as f:
                words = [w.strip() for w in f if w.strip()]
            
            self.logger.info(f"Starting brute-force with {len(words)} words...")
            subdomains = [f"{w}.{domain}" for w in words]
            
            resolved = await self.resolve_list(subdomains, "Brute-forcing")
            valid = [sub for sub, ip in resolved if ip]
            
            self.logger.info(f"{Fore.GREEN}Found {len(valid)} valid subdomains via brute-force{Style.RESET_ALL}")
            return valid
            
        except FileNotFoundError:
            self.logger.error(f"Wordlist not found: {wordlist_path}")
            return []
        except Exception as e:
            self.logger.error(f"Error during brute-force: {e}")
            return []
    
    async def scan(self, domain: str):
        """Main scanning orchestrator"""
        all_subdomains = set()
        
        if not self.args.brute_only:
            crt_subs = await self.run_crtsh(domain)
            all_subdomains.update(crt_subs)
            self.stats['crtsh'] = len(crt_subs)
        
        if self.args.axfr:
            axfr_subs = self.dns_resolver.try_zone_transfer(domain, self.logger)
            all_subdomains.update(axfr_subs)
            self.stats['axfr'] = len(axfr_subs)
        
        if self.args.wordlist and not self.args.crt_only:
            brute_subs = await self.run_bruteforce(domain, self.args.wordlist)
            all_subdomains.update(brute_subs)
            self.stats['bruteforce'] = len(brute_subs)
        
        self.logger.info(f"Resolving {len(all_subdomains)} unique subdomains...")
        resolved = await self.resolve_list(list(all_subdomains), "Resolving all")
        
        for subdomain, ip in resolved:
            if not ip:
                if not self.args.alive_only:
                    self.results.append({
                        'subdomain': subdomain,
                        'ip': None,
                        'status': 'No IP'
                    })
                continue
            
            if self.args.filter and self.args.filter.lower() not in subdomain.lower():
                continue
            if self.args.exclude and self.args.exclude.lower() in subdomain.lower():
                continue
            
            result = await self.analyze_subdomain(subdomain, ip)
            self.results.append(result)
            
            self.display_result(result)
        
        self.stats['total'] = len(self.results)
        self.stats['duration'] = time.time() - self.start_time
    
    def display_result(self, result: Dict):
        """Display a single result in terminal"""
        if self.args.quiet:
            return
        
        subdomain = result['subdomain']
        ip = result.get('ip', 'No IP')
        
        status_parts = []
        if result.get('http_status'):
            status_parts.append(f"HTTP:{result['http_status']}")
        if result.get('https_status'):
            status_parts.append(f"HTTPS:{result['https_status']}")
        
        status_str = ' '.join(status_parts) if status_parts else ''
        
        tech_str = ''
        if result.get('technologies'):
            tech_str = f" [{', '.join(result['technologies'][:3])}]"
        
        takeover_str = ''
        if result.get('takeover_risk'):
            takeover_str = f" {Fore.RED}⚠ TAKEOVER: {result['takeover_risk']}{Style.RESET_ALL}"
        
        port_str = ''
        if result.get('open_ports'):
            port_str = f" Ports: {','.join(map(str, result['open_ports'][:5]))}"
        
        if result.get('https_status') == 200 or result.get('http_status') == 200:
            color = Fore.GREEN
            symbol = '✓'
        elif result.get('https_status') or result.get('http_status'):
            color = Fore.YELLOW
            symbol = '⚠'
        else:
            color = Fore.WHITE
            symbol = '→'
        
        print(f"{color}{symbol} {subdomain}{Style.RESET_ALL} → {ip} {status_str}{tech_str}{port_str}{takeover_str}")
    
    def generate_summary(self):
        """Display scan summary"""
        if self.args.quiet:
            return
        
        duration = f"{self.stats['duration']:.2f}s"
        
        print(f"\n{'=' * 60}")
        print(f"{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{'=' * 60}")
        print(f"Target Domain:           {self.args.url}")
        print(f"Total Subdomains:        {self.stats['total']}")
        print(f"  - From crt.sh:         {self.stats.get('crtsh', 0)}")
        print(f"  - From brute-force:    {self.stats.get('bruteforce', 0)}")
        print(f"  - From AXFR:           {self.stats.get('axfr', 0)}")
        print(f"Scan Duration:           {duration}")
        print(f"{'=' * 60}\n")
    
    def save_results(self):
        """Save results to file in specified format"""
        if not self.args.output:
            return
        
        output_file = self.args.output
        fmt = self.args.format.lower()
        
        try:
            if fmt == 'json':
                self.save_json(output_file)
            elif fmt == 'csv':
                self.save_csv(output_file)
            elif fmt == 'html':
                self.save_html(output_file)
            else: 
                self.save_txt(output_file)
            
            self.logger.info(f"{Fore.GREEN}Results saved to: {output_file}{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
    
    def save_txt(self, filename: str):
        """Save as plain text"""
        with open(filename, 'w') as f:
            f.write(f"SAYN Scan Results - {datetime.now()}\n")
            f.write(f"Target: {self.args.url}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in self.results:
                subdomain = result['subdomain']
                ip = result.get('ip', 'No IP')
                f.write(f"{subdomain} → {ip}\n")
                
                if result.get('http_status'):
                    f.write(f"  HTTP Status: {result['http_status']}\n")
                if result.get('https_status'):
                    f.write(f"  HTTPS Status: {result['https_status']}\n")
                if result.get('technologies'):
                    f.write(f"  Technologies: {', '.join(result['technologies'])}\n")
                if result.get('open_ports'):
                    f.write(f"  Open Ports: {', '.join(map(str, result['open_ports']))}\n")
                if result.get('takeover_risk'):
                    f.write(f"  ⚠ Takeover Risk: {result['takeover_risk']}\n")
                f.write("\n")
    
    def save_json(self, filename: str):
        """Save as JSON"""
        data = {
            'scan_info': {
                'target': self.args.url,
                'timestamp': datetime.now().isoformat(),
                'duration': f"{self.stats['duration']:.2f}s",
                'version': VERSION
            },
            'statistics': dict(self.stats),
            'subdomains': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    def save_csv(self, filename: str):
        """Save as CSV"""
        if not self.results:
            return
        
        with open(filename, 'w', newline='') as f:
            fieldnames = ['subdomain', 'ip', 'http_status', 'https_status', 
                         'technologies', 'open_ports', 'takeover_risk']
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            
            writer.writeheader()
            for result in self.results:
                row = result.copy()
                if 'technologies' in row:
                    row['technologies'] = ', '.join(row['technologies'])
                if 'open_ports' in row:
                    row['open_ports'] = ', '.join(map(str, row['open_ports']))
                writer.writerow(row)
    
    def save_html(self, filename: str):
        """Save as interactive HTML dashboard"""
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAYN Scan Report - {self.args.url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f0f23; color: #e0e0e0; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ color: white; margin-bottom: 10px; }}
        .header p {{ color: #f0f0f0; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #1a1a2e; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }}
        .stat-card h3 {{ color: #667eea; font-size: 14px; margin-bottom: 10px; }}
        .stat-card .value {{ font-size: 32px; font-weight: bold; }}
        .search-box {{ margin-bottom: 20px; }}
        .search-box input {{ width: 100%; padding: 12px; background: #1a1a2e; border: 2px solid #667eea; color: #e0e0e0; border-radius: 6px; font-size: 16px; }}
        table {{ width: 100%; background: #1a1a2e; border-radius: 8px; overflow: hidden; }}
        th {{ background: #667eea; color: white; padding: 15px; text-align: left; }}
        td {{ padding: 12px; border-bottom: 1px solid #2a2a3e; }}
        tr:hover {{ background: #2a2a3e; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; margin: 2px; }}
        .badge-success {{ background: #10b981; color: white; }}
        .badge-warning {{ background: #f59e0b; color: white; }}
        .badge-danger {{ background: #ef4444; color: white; }}
        .badge-info {{ background: #3b82f6; color: white; }}
        .footer {{ text-align: center; margin-top: 40px; padding: 20px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 SAYN Scan Report</h1>
            <p>Target: {self.args.url} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Subdomains</h3>
                <div class="value">{self.stats['total']}</div>
            </div>
            <div class="stat-card">
                <h3>From crt.sh</h3>
                <div class="value">{self.stats.get('crtsh', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>From Brute-force</h3>
                <div class="value">{self.stats.get('bruteforce', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>Scan Duration</h3>
                <div class="value">{self.stats['duration']:.1f}s</div>
            </div>
        </div>
        
        <div class="search-box">
            <input type="text" id="searchInput" placeholder="🔍 Search subdomains..." onkeyup="filterTable()">
        </div>
        
        <table id="resultsTable">
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Technologies</th>
                    <th>Ports</th>
                    <th>Risks</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for result in self.results:
            subdomain = result['subdomain']
            ip = result.get('ip', 'N/A')
            
            status_html = ''
            if result.get('http_status'):
                status_html += f'<span class="badge badge-info">HTTP: {result["http_status"]}</span>'
            if result.get('https_status'):
                status_html += f'<span class="badge badge-success">HTTPS: {result["https_status"]}</span>'
            
            tech_html = ''
            if result.get('technologies'):
                for tech in result['technologies']:
                    tech_html += f'<span class="badge badge-info">{tech}</span>'
            
            port_html = ''
            if result.get('open_ports'):
                for port in result['open_ports']:
                    port_html += f'<span class="badge badge-warning">{port}</span>'
            
            risk_html = ''
            if result.get('takeover_risk'):
                risk_html = f'<span class="badge badge-danger">⚠ {result["takeover_risk"]}</span>'
            
            html_template += f"""
                <tr>
                    <td>{subdomain}</td>
                    <td>{ip}</td>
                    <td>{status_html if status_html else 'N/A'}</td>
                    <td>{tech_html if tech_html else 'N/A'}</td>
                    <td>{port_html if port_html else 'N/A'}</td>
                    <td>{risk_html if risk_html else 'N/A'}</td>
                </tr>
"""
        
        html_template += """
            </tbody>
        </table>
        
        <div class="footer">
            <p>Generated by SAYN v""" + VERSION + """ - Powered by M.Nurlan</p>
            <p>Email: nurlanmammadli2@gmail.com | LinkedIn: www.linkedin.com/in/nurlan-məmmədli-b6a55b308</p>
        </div>
    </div>
    
    <script>
        function filterTable() {
            const input = document.getElementById('searchInput');
            const filter = input.value.toLowerCase();
            const table = document.getElementById('resultsTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(filter) ? '' : 'none';
            }
        }
    </script>
</body>
</html>"""
        
        with open(filename, 'w') as f:
            f.write(html_template)

# ==========================================
# MAIN ENTRY POINT
# ==========================================
async def main():
    """Main application entry point"""
    
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="SAYN - Advanced Subdomain Discovery and Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python3 sayn.py -u example.com
  
  Full scan with all features:
    python3 sayn.py -u example.com -w wordlist.txt --probe --tech --ports --takeover -o results.json
  
  Generate HTML report:
    python3 sayn.py -u example.com --full-scan --format html -o report.html
  
  Stealth mode:
    python3 sayn.py -u example.com --concurrency 5 --delay 1000 --quiet

Author: M.Nurlan
Email: nurlanmammadli2@gmail.com
LinkedIn: www.linkedin.com/in/nurlan-məmmədli-b6a55b308
"""
    )
    
    parser.add_argument("-u", "--url", required=True, help="Target domain (required)")
    
    discovery = parser.add_argument_group('Discovery Options')
    discovery.add_argument("-w", "--wordlist", help="Path to wordlist file for brute-forcing")
    discovery.add_argument("--crt-only", action="store_true", help="Only fetch from Certificate Transparency")
    discovery.add_argument("--brute-only", action="store_true", help="Only perform brute-force discovery")
    discovery.add_argument("--axfr", action="store_true", help="Attempt DNS zone transfer (AXFR)")
    discovery.add_argument("--recursive", action="store_true", help="Enable recursive subdomain discovery")
    
    analysis = parser.add_argument_group('Analysis Options')
    analysis.add_argument("--probe", action="store_true", help="Check HTTP/HTTPS availability and status codes")
    analysis.add_argument("--tech", dest="probe", action="store_true", help="Detect web technologies (alias for --probe)")
    analysis.add_argument("--ports", action="store_true", help="Scan common ports")
    analysis.add_argument("--ssl", action="store_true", help="Analyze SSL/TLS certificates")
    analysis.add_argument("--takeover", action="store_true", help="Check for potential subdomain takeovers")
    analysis.add_argument("--full-scan", action="store_true", help="Enable all analysis features")
    
    performance = parser.add_argument_group('Performance Options')
    performance.add_argument("--concurrency", type=int, default=50, help="Max concurrent operations (default: 50)")
    performance.add_argument("--timeout", type=int, default=5, help="HTTP timeout in seconds (default: 5)")
    performance.add_argument("--retries", type=int, default=2, help="DNS retry attempts (default: 2)")
    performance.add_argument("--delay", type=int, default=0, help="Delay between requests in ms (default: 0)")
    performance.add_argument("--dns-server", help="Custom DNS server IP")
    
    output = parser.add_argument_group('Output Options')
    output.add_argument("-o", "--output", help="Save results to file")
    output.add_argument("--format", choices=['txt', 'json', 'csv', 'html'], default='txt', 
                       help="Output format (default: txt)")
    output.add_argument("--verbose", action="store_true", help="Enable verbose output")
    output.add_argument("--quiet", action="store_true", help="Minimal output (errors only)")
    output.add_argument("--no-color", action="store_true", help="Disable colored output")
    
    filtering = parser.add_argument_group('Filtering Options')
    filtering.add_argument("--filter", help="Only show subdomains matching pattern")
    filtering.add_argument("--exclude", help="Exclude subdomains matching pattern")
    filtering.add_argument("--alive-only", action="store_true", help="Only show subdomains with active HTTP/HTTPS")
    
    advanced = parser.add_argument_group('Advanced Options')
    advanced.add_argument("--user-agent", help="Custom User-Agent header")
    advanced.add_argument("--proxy", help="Use proxy (http://proxy:port)")
    
    args = parser.parse_args()
    
    logger = setup_logging(args.verbose, args.quiet)
    
    if args.no_color:
        init(strip=True, convert=False)
    
    if args.full_scan:
        args.probe = True
        args.ports = True
        args.takeover = True
        args.ssl = True
        args.axfr = True
    
    if args.brute_only and not args.wordlist:
        logger.error("--brute-only requires --wordlist")
        return
    
    domain = args.url.strip().lower()
    logger.info(f"Starting scan on: {Fore.CYAN}{domain}{Style.RESET_ALL}")
    
    scanner = SubdomainScanner(args, logger)
    
    try:
        await scanner.scan(domain)
        scanner.generate_summary()
        scanner.save_results()
        
        logger.info(f"{Fore.GREEN}Scan completed successfully!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        logger.warning(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        scanner.generate_summary()
        if args.output:
            logger.info("Saving partial results...")
            scanner.save_results()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

# ==========================================
# SCRIPT EXECUTION
# ==========================================
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user. Exiting...{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
