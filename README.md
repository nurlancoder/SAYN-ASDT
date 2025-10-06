# SAYN 🔍
*Subdomain Analysis & discovery Yielding Network intelligence*

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()
[![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)]()

**Powered by M.Nurlan**  
📧 Email: nurlanmammadli2@gmail.com  
💼 LinkedIn: [www.linkedin.com/in/nurlan-məmmədli-b6a55b308](https://www.linkedin.com/in/nurlan-məmmədli-b6a55b308)

---

## 📖 Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [Command-Line Options](#-command-line-options)
- [Examples](#-examples)
- [Output Formats](#-output-formats)
- [Screenshots](#-screenshots)
- [Performance Tips](#-performance-tips)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## 🌟 Overview

**SAYN** (Subdomain Analysis & discovery Yielding Network intelligence) is a next-generation, asynchronous subdomain enumeration and analysis framework designed for security researchers, penetration testers, and network administrators.

Unlike traditional subdomain scanners, SAYN combines multiple reconnaissance techniques with advanced analysis capabilities to provide comprehensive intelligence about target domains.

### Why SAYN?

- 🚀 **Blazing Fast**: Asynchronous architecture with concurrent processing
- 🎯 **Multi-Source Intelligence**: Combines Certificate Transparency, DNS brute-force, and zone transfers
- 🔍 **Deep Analysis**: HTTP probing, technology fingerprinting, port scanning, and vulnerability detection
- 📊 **Beautiful Reports**: Interactive HTML dashboards with real-time search and filtering
- 🛡️ **Security-Focused**: Detects subdomain takeover vulnerabilities and misconfigurations
- 🎨 **User-Friendly**: Color-coded output, progress bars, and intuitive CLI

---

## ✨ Features

### 🎯 Discovery Methods

#### 1. Certificate Transparency (crt.sh)
- Queries public CT logs for SSL/TLS certificates
- Discovers historical and active subdomains
- No authentication required

#### 2. DNS Brute-Force
- Custom wordlist support
- Concurrent DNS resolution
- Smart retry mechanism
- Progress tracking

#### 3. Zone Transfer (AXFR)
- Attempts DNS zone transfer
- Discovers internal subdomains
- Tests misconfigured DNS servers

#### 4. Recursive Discovery
- Finds subdomains of subdomains
- Deep enumeration capabilities

### 🔬 Analysis Features

#### HTTP/HTTPS Probing
- ✅ Status code detection (200, 301, 403, 404, 500, etc.)
- ✅ SSL/TLS validation
- ✅ Redirect chain following
- ✅ Title extraction
- ✅ Response time measurement

#### Technology Fingerprinting
Automatically detects:
- **Web Servers**: Apache, Nginx, IIS, LiteSpeed
- **Frameworks**: Node.js, PHP, Python, Ruby
- **CMS**: WordPress, Joomla, Drupal, Shopify
- **Technologies**: React, Vue.js, Angular
- **CDN**: Cloudflare, Akamai, Fastly

#### Port Scanning
- Scans common ports: 80, 443, 8080, 8443, 3000, 5000, 8000, 8888
- Asynchronous port probing
- Custom port list support

#### Subdomain Takeover Detection
Checks for vulnerabilities in:
- AWS S3 Buckets
- GitHub Pages
- Heroku Apps
- Azure Websites
- Shopify Stores
- Tumblr Blogs
- WordPress.com sites

### 📊 Reporting & Export

#### Multiple Output Formats
1. **TXT** - Simple text format for easy reading
2. **JSON** - Structured data for automation
3. **CSV** - Spreadsheet compatible format
4. **HTML** - Interactive dashboard with charts

#### Interactive HTML Dashboard Features
- 📊 Visual statistics and charts
- 🔍 Real-time search and filtering
- 📥 One-click export to various formats
- 🎨 Responsive design (mobile-friendly)
- 🌓 Clean, modern interface
- ⚡ Fast client-side operations

### ⚡ Performance Features

- **Concurrent Processing**: Process hundreds of subdomains simultaneously
- **Rate Limiting**: Respect target server limits
- **Smart Retry**: Automatic retry for failed queries
- **Custom DNS**: Use your preferred DNS resolver
- **Proxy Support**: Route traffic through proxy servers
- **Resource Efficient**: Optimized memory and CPU usage

### 🎨 User Experience

- **Color-Coded Output**: Easy to read terminal display
- **Progress Bars**: Real-time progress tracking with tqdm
- **Verbose Mode**: Detailed debugging information
- **Quiet Mode**: Minimal output for automation
- **Error Handling**: Graceful error recovery
- **Keyboard Interrupt**: Save partial results on Ctrl+C

---

## 🛠️ Installation

### Prerequisites

- **Python**: 3.8 or higher
- **Operating System**: Linux, macOS, or Windows
- **Internet Connection**: Required for external data sources

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/SAYN.git
cd SAYN
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install aiohttp colorama tqdm dnspython beautifulsoup4 requests
```

### Step 3: Make Executable (Linux/macOS)

```bash
chmod +x sayn.py
```

### Verification

```bash
python3 sayn.py --help
```

---

## 🚀 Quick Start

### Basic Scan

Discover subdomains using Certificate Transparency:

```bash
python3 sayn.py -u example.com
```

### Save Results

Save discovered subdomains to a file:

```bash
python3 sayn.py -u example.com -o results.txt
```

### Brute-Force with Wordlist

Combine CT logs with brute-force:

```bash
python3 sayn.py -u example.com -w wordlist.txt
```

### Full Reconnaissance

Enable all features:

```bash
python3 sayn.py -u example.com -w wordlist.txt --full-scan -o report.html --format html
```

---

## 📚 Usage Guide

### Basic Syntax

```bash
python3 sayn.py -u <domain> [options]
```

### Common Workflows

#### 1. Passive Reconnaissance
```bash
python3 sayn.py -u target.com --crt-only --probe -o passive.json --format json
```
Only uses public data sources (Certificate Transparency).

#### 2. Active Enumeration
```bash
python3 sayn.py -u target.com -w /usr/share/wordlists/subdomains.txt --brute-only
```
Performs active DNS brute-forcing.

#### 3. Comprehensive Scan
```bash
python3 sayn.py -u target.com \
  -w wordlist.txt \
  --probe \
  --ports \
  --takeover \
  --axfr \
  -o comprehensive.html \
  --format html
```
Full reconnaissance with all features enabled.

#### 4. Stealth Mode
```bash
python3 sayn.py -u target.com \
  --concurrency 5 \
  --delay 1000 \
  --rate-limit 10 \
  --quiet
```
Slow, careful scanning to avoid detection.

#### 5. Live Subdomain Check
```bash
python3 sayn.py -u target.com --probe --alive-only
```
Only shows subdomains with active web servers.

---

## 🎛️ Command-Line Options

### Required Arguments

| Option | Description |
|--------|-------------|
| `-u`, `--url` | Target domain (required) |

### Discovery Options

| Option | Description |
|--------|-------------|
| `-w`, `--wordlist` | Path to wordlist file for brute-forcing |
| `--crt-only` | Only fetch from Certificate Transparency |
| `--brute-only` | Only perform brute-force discovery |
| `--axfr` | Attempt DNS zone transfer (AXFR) |
| `--recursive` | Enable recursive subdomain discovery |

### Analysis Options

| Option | Description |
|--------|-------------|
| `--probe` | Check HTTP/HTTPS availability and status codes |
| `--tech` | Detect web technologies (alias for --probe) |
| `--ports` | Scan common ports (80, 443, 8080, etc.) |
| `--ssl` | Analyze SSL/TLS certificates |
| `--takeover` | Check for potential subdomain takeovers |
| `--full-scan` | Enable all analysis features |

### Performance Options

| Option | Default | Description |
|--------|---------|-------------|
| `--concurrency N` | 50 | Max concurrent operations |
| `--timeout N` | 5 | HTTP timeout in seconds |
| `--retries N` | 2 | DNS retry attempts |
| `--delay N` | 0 | Delay between requests (ms) |
| `--dns-server IP` | - | Custom DNS server |

### Output Options

| Option | Description |
|--------|-------------|
| `-o`, `--output FILE` | Save results to file |
| `--format FORMAT` | Output format: txt, json, csv, html (default: txt) |
| `--verbose` | Enable verbose output |
| `--quiet` | Minimal output (errors only) |
| `--no-color` | Disable colored output |

### Filtering Options

| Option | Description |
|--------|-------------|
| `--filter PATTERN` | Only show subdomains matching pattern |
| `--exclude PATTERN` | Exclude subdomains matching pattern |
| `--alive-only` | Only show subdomains with active HTTP/HTTPS |

### Advanced Options

| Option | Description |
|--------|-------------|
| `--user-agent STRING` | Custom User-Agent header |
| `--proxy URL` | Use proxy (http://proxy:port) |

---

## 💡 Examples

### Example 1: Basic Discovery
```bash
python3 sayn.py -u example.com -o subdomains.txt
```
**Output**: Discovers subdomains from crt.sh and saves to text file.

---

### Example 2: Wordlist Brute-Force
```bash
python3 sayn.py -u example.com -w /usr/share/wordlists/subdomains-top5000.txt
```
**Output**: Tests 5000 common subdomain names.

---

### Example 3: Full Reconnaissance with HTML Report
```bash
python3 sayn.py -u example.com \
  -w wordlist.txt \
  --probe \
  --tech \
  --ports \
  --takeover \
  -o full_report.html \
  --format html \
  --verbose
```
**Output**: Comprehensive scan with interactive HTML dashboard.

---

### Example 4: Only Active Subdomains
```bash
python3 sayn.py -u example.com --probe --alive-only -o active_subs.json --format json
```
**Output**: JSON file containing only subdomains with active HTTP/HTTPS.

---

### Example 5: Stealth Scan
```bash
python3 sayn.py -u example.com \
  -w small_wordlist.txt \
  --concurrency 3 \
  --delay 2000 \
  --timeout 10 \
  --quiet
```
**Output**: Slow, careful scan with minimal output.

---

### Example 6: Custom DNS Server
```bash
python3 sayn.py -u example.com --dns-server 8.8.8.8 --probe
```
**Output**: Uses Google DNS (8.8.8.8) for resolution.

---

### Example 7: Check for Takeover Vulnerabilities
```bash
python3 sayn.py -u example.com --crt-only --takeover -o takeover_check.txt
```
**Output**: Checks all crt.sh subdomains for takeover risks.

---

### Example 8: Port Scan Active Subdomains
```bash
python3 sayn.py -u example.com --probe --alive-only --ports
```
**Output**: Scans common ports on all active subdomains.

---

### Example 9: Filter Specific Subdomains
```bash
python3 sayn.py -u example.com --filter "admin" -o admin_subs.txt
```
**Output**: Only shows subdomains containing "admin".

---

### Example 10: Export to CSV
```bash
python3 sayn.py -u example.com -w wordlist.txt --probe --format csv -o results.csv
```
**Output**: Spreadsheet-compatible CSV file.

---

## 📊 Output Formats

### 1. Text Format (TXT)

Simple, human-readable format:

```
SAYN Scan Results - 2025-10-06 15:30:45
Target: example.com
================================================================================

api.example.com → 203.0.113.45
  HTTP Status: 200
  HTTPS Status: 200
  Technologies: Nginx, PHP
  Open Ports: 80, 443

blog.example.com → 203.0.113.46
  HTTP Status: 200
  HTTPS Status: 200
  Technologies: WordPress, Apache
```

---

### 2. JSON Format

Structured data for automation:

```json
{
  "scan_info": {
    "target": "example.com",
    "timestamp": "2025-10-06T15:30:45Z",
    "duration": "158.42s",
    "version": "2.0.0"
  },
  "statistics": {
    "total": 134,
    "crtsh": 127,
    "bruteforce": 7
  },
  "subdomains": [
    {
      "subdomain": "api.example.com",
      "ip": "203.0.113.45",
      "http_status": 200,
      "https_status": 200,
      "technologies": ["Nginx", "PHP"],
      "open_ports": [80, 443, 8080],
      "takeover_risk": null
    }
  ]
}
```

---

### 3. CSV Format

Spreadsheet-compatible:

```csv
subdomain,ip,http_status,https_status,technologies,open_ports,takeover_risk
api.example.com,203.0.113.45,200,200,"Nginx, PHP","80, 443",
blog.example.com,203.0.113.46,200,200,"WordPress, Apache","80, 443",
staging.example.com,10.0.0.15,200,200,Node.js,"3000",
```

---

### 4. HTML Format

Interactive dashboard with:
- 📊 Visual statistics cards
- 🔍 Real-time search functionality
- 🎨 Color-coded status indicators
- 📱 Responsive design
- 💾 Client-side filtering

---

## 📸 Screenshots

### Terminal Output
```
  ____    _    __   ___   _ 
 / ___|  / \   \ \ / / \ | |
 \___ \ / _ \   \ V /|  \| |
  ___) / ___ \   | | | |\  |
 |____/_/   \_\  |_| |_| \_|

[+] SAYN v2.0.0 - Advanced Subdomain Discovery Tool
[+] Powered by M.Nurlan
[+] Target: example.com

[INFO] 15:42:33 - Searching Certificate Transparency logs...
[INFO] 15:42:35 - Found 127 subdomains from crt.sh

Resolving subdomains: 100%|████████████| 127/127 [00:08<00:00, 15.2sub/s]

✓ api.example.com → 203.0.113.45 HTTP:200 HTTPS:200 [Nginx, PHP]
✓ blog.example.com → 203.0.113.46 HTTP:200 HTTPS:200 [WordPress]
⚠ old.example.com → 203.0.113.47 HTTP:404
✓ shop.example.com → 203.0.113.48 HTTP:200 HTTPS:200 [Shopify]

[INFO] 15:42:45 - Starting brute-force with 5000 words...

Brute-forcing: 100%|███████████████| 5000/5000 [01:23<00:00, 60.2sub/s]

✓ admin.example.com → 203.0.113.89 HTTP:403 [Apache]
⚠ staging.example.com → CNAME to s3.amazonaws.com ⚠ TAKEOVER: AWS S3

============================================================
SCAN SUMMARY
============================================================
Target Domain:           example.com
Total Subdomains:        134
  - From crt.sh:         127
  - From brute-force:    7
  - From AXFR:           0
Scan Duration:           158.42s
============================================================

[SUCCESS] Results saved to: results.json
```

---

## ⚡ Performance Tips

### Optimize Concurrency

**For fast networks:**
```bash
python3 sayn.py -u example.com --concurrency 100
```

**For slow networks:**
```bash
python3 sayn.py -u example.com --concurrency 20
```

### Use Custom DNS Servers

**Google DNS:**
```bash
python3 sayn.py -u example.com --dns-server 8.8.8.8
```

**Cloudflare DNS:**
```bash
python3 sayn.py -u example.com --dns-server 1.1.1.1
```

### Add Delays for Rate Limiting

```bash
python3 sayn.py -u example.com --delay 500  # 500ms delay
```

### Use Efficient Wordlists

**Small wordlist (fast):**
```bash
python3 sayn.py -u example.com -w subdomains-top1000.txt
```

**Large wordlist (comprehensive):**
```bash
python3 sayn.py -u example.com -w subdomains-top100000.txt
```

---

## 🐛 Troubleshooting

### Issue: DNS Resolution Failures

**Solution 1**: Use custom DNS server
```bash
python3 sayn.py -u example.com --dns-server 1.1.1.1
```

**Solution 2**: Increase retries
```bash
python3 sayn.py -u example.com --retries 5
```

---

### Issue: Rate Limiting

**Solution**: Reduce concurrency and add delay
```bash
python3 sayn.py -u example.com --concurrency 10 --delay 1000
```

---

### Issue: Timeout Errors

**Solution**: Increase timeout
```bash
python3 sayn.py -u example.com --timeout 10
```

---

### Issue: SSL Certificate Errors

**Solution**: Currently SSL verification is disabled by default for compatibility

---

### Issue: Permission Denied

**Solution**: Run with appropriate permissions
```bash
sudo python3 sayn.py -u example.com --ports
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Areas for Improvement
- 🔍 Additional data source integrations
- 🛡️ Enhanced vulnerability detection
- 📊 More export format options
- ⚡ Performance optimizations
- 📚 Documentation improvements
- 🌐 Internationalization (i18n)

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License.

```
MIT License

Copyright (c) 2025 M.Nurlan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## ⚠️ Legal Disclaimer

### Important Notice

**SAYN is designed for authorized security testing and research purposes only.**

- ✅ **DO** use on domains you own
- ✅ **DO** obtain written permission before testing
- ✅ **DO** respect rate limits and ToS
- ✅ **DO** use responsibly and ethically

- ❌ **DON'T** scan domains without authorization
- ❌ **DON'T** use for malicious purposes
- ❌ **DON'T** violate laws or regulations
- ❌ **DON'T** overwhelm target servers

**Users are responsible for complying with all applicable laws and regulations.**

---

## 👤 Author

**M.Nurlan**  
*Cybersecurity Enthusiast | Network Security Researcher*

📧 **Email**: nurlanmammadli2@gmail.com  
💼 **LinkedIn**: [www.linkedin.com/in/nurlan-məmmədli-b6a55b308](https://www.linkedin.com/in/nurlan-məmmədli-b6a55b308)  
🌐 **GitHub**: [@yourusername](https://github.com/yourusername)

---

## 🌟 Acknowledgments

- Original inspiration from various subdomain enumeration tools
- Built with ❤️ for the security research community
- Thanks to all contributors and users

---

## 📞 Support

Need help? Have questions?

- 📧 **Email**: nurlanmammadli2@gmail.com
- 💼 **LinkedIn**: [Connect with me](https://www.linkedin.com/in/nurlan-məmmədli-b6a55b308)
- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/SAYN/issues)

---

## 🎯 Roadmap

### Version 2.1 (Planned)
- [ ] Integration with Shodan API
- [ ] Enhanced subdomain takeover detection
- [ ] Screenshot capture for active subdomains
- [ ] API endpoint discovery
- [ ] Subdomain monitoring mode

### Version 3.0 (Future)
- [ ] Machine learning for pattern detection
- [ ] Cloud storage integration (AWS S3, Azure Blob)
- [ ] Team collaboration features
- [ ] RESTful API server mode
- [ ] Web-based GUI

---

## 📈 Statistics

![GitHub stars](https://img.shields.io/github/stars/yourusername/SAYN?style=social)
![GitHub forks](https://img.shields.io/github/forks/yourusername/SAYN?style=social)
![GitHub issues](https://img.shields.io/github/issues/yourusername/SAYN)
![GitHub pull requests](https://img.shields.io/github/issues-pr/yourusername/SAYN)

---

**⭐ If you find SAYN useful, please consider giving it a star on GitHub!**

---

<div align="center">

### Made with ❤️ by M.Nurlan

**SAYN v2.0.0** - *Discover. Analyze. Secure.*

[⬆ Back to Top](#sayn-)

</div>

---

*Last Updated: October 6, 2025*
