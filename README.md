#  Sub-Kamuna 

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/subkamuna)
[![Node.js](https://img.shields.io/badge/Node.js-14%2B-green.svg)](https://nodejs.org)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **Professional subdomain enumeration tool with HTTP probing, file/folder discovery, technology detection, and real-time HTML reports**

##  Table of Contents
- [ Features](#-features)
- [ Prerequisites](#-prerequisites)
- [ Quick Installation](#-quick-installation)
- [ Quick Start](#-quick-start)
- [ Command Reference](#-command-reference)
- [ Feature Guide](#-feature-guide)
- [ Output Examples](#-output-examples)
- [ Use Cases](#-use-cases)
- [ Pipeline Integration](#-pipeline-integration)
- [ Troubleshooting](#-troubleshooting)
- [ FAQ](#-faq)
- [ Project Structure](#-project-structure)
- [ License](#-license)

---

##  Features

| Category | Features |
|----------|----------|
| Subdomain Discovery | Subfinder integration + DNS brute force (200+ wordlist) |
| HTTP Probing | HTTP/HTTPS checks, status codes, response time, headers |
| File Discovery | robots.txt, .env, config files, backups, source code |
| Folder Discovery | Admin panels, API endpoints, hidden directories |
| Email Extraction | Extract emails from HTML and JavaScript files |
| Tech Detection | Identify 25+ technologies (CMS, frameworks, servers) |
| JS Endpoints | Extract API endpoints from JavaScript files |
| Auto-Save | Multiple formats: TXT, JSON, CSV, HTML |
| Performance | Configurable threading (1-500 threads) |
| UI | Colored output, progress bars, spinners |
| Pipeline Ready | Silent mode for tool chaining |
| Cross-Platform | Windows, Linux, macOS |

---

##  Prerequisites

- Node.js (v14 or higher)
- Download from: [https://nodejs.org/](https://nodejs.org/)

### Optional (For better performance)
- Subfinder - Fast subdomain discovery
```bash
# Install Go first, then:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```
##  Quick Installation
```bash
git clone https://github.com/menmengleap/sub-kamuna.git
cd subkamuna
npm install
```
##  Test Simple Scan
```bash
node bin/subkamuna.js example.com --only-live
```
##  Quick Start
```bash
# Scan a single domain
node bin/subkamuna.js example.com

# Show only live domains
node bin/subkamuna.js example.com --only-live

# Skip HTTP probing (subdomains only)
node bin/subkamuna.js example.com --no-http

# Verbose output
node bin/subkamuna.js example.com -v

# Silent mode (for pipeline)
node bin/subkamuna.js example.com -s --only-live
```
##  Full Reconnaissance
```bash
# All features enabled
node bin/subkamuna.js example.com \
  --scan-files \
  --scan-folders \
  --email-extract \
  --tech-detect \
  --real-report \
  --csv-export \
  --only-live \
  -t 100 \
  -v
```
##  Multi-Domain Scan
```bash
# Create domains file
echo "example.com" > domains.txt
echo "google.com" >> domains.txt
echo "github.com" >> domains.txt

# Scan all domains
node bin/subkamuna.js -l domains.txt --only-live
```
##  Command Reference
![App Screenshot](SubKamuna/Screenshot%202026-04-21%20193849.png)
![App Screenshot](SubKamuna/Screenshot%202026-04-21%20193900.png)
##  Feature Guide
1 SubKamuna uses a dual approach for maximum coverage:
```bash
# Automatic mode (Subfinder → DNS brute force)
node bin/subkamuna.js example.com

# Force DNS brute force (remove subfinder)
# Tool automatically falls back
```
! Wordlist Categories (200+ words):

+ Standard: www, mail, ftp, admin, blog, dev, api

+ Admin: wp-admin, cpanel, administrator, dashboard, control

+ Development: staging, test, dev, sandbox, uat, qa

+ Services: smtp, imap, vpn, proxy, gateway, firewall

+ Security: auth, login, sso, oauth, ldap, cert

+ Storage: cdn, static, assets, storage, db, backup

+ Business: shop, store, payment, billing, account

2. HTTP Probing
```bash
  # Basic probing with status codes
node bin/subkamuna.js example.com

# Detailed probing with response time and headers
node bin/subkamuna.js example.com -v
```
Information Displayed:

+ Status codes (200, 301, 404, 500, etc.)

+ Response time in milliseconds

+ Server headers (Apache, Nginx, Cloudflare)

+ Content type (HTML, JSON, XML)

+ Page title

+ Content length

3. File Discovery
```bash
node bin/subkamuna.js example.com --scan-files
```
4. Files Discovered (50+ types):

Category	Files
Configuration	.env, .htaccess, web.config, app.config, config.json
Documentation	README.md, LICENSE, CHANGELOG.md, CONTRIBUTING.md
Security	robots.txt, security.txt, crossdomain.xml
Backups	backup.zip, backup.sql, dump.sql, database.sql
Source Code	package.json, composer.json, wp-config.php
Debug	phpinfo.php, info.php, test.php, debug.php
Docker	Dockerfile, docker-compose.yml, .dockerignore
CI/CD	.travis.yml, .gitlab-ci.yml, Jenkinsfile

5. Folder Discovery
```bash
node bin/subkamuna.js example.com --scan-folders --depth 3
```
## Directories Discovered (40+ types):

Category	Directories
Admin	/admin, /wp-admin, /administrator, /dashboard, /cpanel
API	/api, /v1, /v2, /v3, /graphql, /swagger, /rest
Development	/dev, /staging, /test, /qa, /sandbox, /uat
Hidden	/secret, /private, /internal, /hidden, /confidential
Assets	/uploads, /images, /assets, /static, /public, /downloads
System	/backup, /temp, /tmp, /cache, /logs, /debug
5. Technology Detection
```bash
node bin/subkamuna.js example.com --tech-detect
```
## Technologies Detected (30+ types):

Category	Technologies
CMS	WordPress, Drupal, Joomla, Magento, Shopify
Frameworks	Laravel, React, Angular, Vue.js, Express.js, Django, Ruby on Rails
Servers	Nginx, Apache, Microsoft IIS, Cloudflare, AWS
Libraries	jQuery, Bootstrap, Tailwind, React, Angular
Analytics	Google Analytics, Facebook Pixel, Hotjar
Security	Cloudflare, Sucuri, Akamai, Incapsula

6. Email Extraction
```bash
node bin/subkamuna.js example.com --email-extract
```
Extracts email addresses from:

HTML pages (contact, about, team pages)

JavaScript files

JSON responses

Comment sections

7. JavaScript Endpoint Extraction
```bash
node bin/subkamuna.js example.com --js-extract
```
Discovers API endpoints from:

JavaScript files (internal and external)

Inline scripts

AJAX/Fetch calls

WebSocket URLs

API route definitions

8. Real HTML Report
```bash
node bin/subkamuna.js example.com --real-report
```
Report Features:

## Interactive statistics dashboard

- Expandable domain sections

- Live subdomains list with status codes

- Discovered files and folders

- Extracted emails

- Detected technologies

- Export to JSON

- Print-friendly layout

- Responsive design

- Output Examples

Console Output

![App Screenshot](https://github.com/menmengleap/sub-kamuna/blob/main/SubKamuna/Screenshot%202026-04-21%20151806.png)                                                                      
## Use Cases
1. Bug Bounty Hunting
```bash
# Quick reconnaissance on target
node bin/subkamuna.js target.com --only-live -v

# Full asset discovery
node bin/subkamuna.js target.com \
  --scan-files \
  --scan-folders \
  --tech-detect \
  --only-live \
  -t 100
```
2. Security Assessment
```bash
# Comprehensive security scan
node bin/subkamuna.js company.com \
  --scan-files \
  --scan-folders \
  --email-extract \
  --tech-detect \
  --real-report \
  -v
```
3. Asset Discovery
```bash
# Discover all assets for a company
node bin/subkamuna.js -l company-domains.txt \
  --only-live \
  --csv-export \
  -o company-assets.json
```
4. Continuous Monitoring
```bash
# Create monitoring script (monitor.bat)
@echo off
set DATE=%date:/=-%
node bin/subkamuna.js -l monitored-domains.txt \
  --only-live \
  --real-report \
  -o "scan_%DATE%.json"
echo Scan completed on %DATE%
```
5. CI/CD Pipeline Integration
```bash
# Pre-deployment security check
node bin/subkamuna.js staging.myapp.com \
  --only-live \
  -s | findstr "200"

if %errorlevel% equ 0 (
  echo " All services operational"
  exit 0
) else (
  echo " Issues detected!"
  exit 1
)
```
6. Research Project
```bash
# Scan multiple research targets
node bin/subkamuna.js -l research-targets.txt \
  --tech-detect \
  --csv-export \
  --real-report \
  -t 50
 Pipeline Integration
Windows (CMD)
bash
# Find only 200 OK responses
node bin/subkamuna.js example.com --only-live -s | findstr "200"

# Count live domains
node bin/subkamuna.js example.com --only-live -s | find /c "http"

# Extract URLs only
node bin/subkamuna.js example.com --only-live -s | findstr "https\?://"

# Save to file
node bin/subkamuna.js example.com --only-live -s > live-domains.txt
PowerShell
powershell
# Filter by status code
node bin/subkamuna.js example.com --only-live -s | Select-String "200"

# Export to CSV
node bin/subkamuna.js example.com --only-live -s | ConvertFrom-Csv | Export-Csv results.csv

# Send email notification
$results = node bin/subkamuna.js example.com --only-live -s
Send-MailMessage -To "admin@example.com" -Subject "Scan Results" -Body $results

# Filter and count
node bin/subkamuna.js example.com --only-live -s | Measure-Object -Line
Linux / macOS
bash
# Use with grep
node bin/subkamuna.js example.com --only-live -s | grep "200"

# Use with awk
node bin/subkamuna.js example.com --only-live -s | awk '{print $1}'

# Use with jq for JSON
node bin/subkamuna.js example.com -o - | jq '.live_subdomains'

# Count with wc
node bin/subkamuna.js example.com --only-live -s | wc -l
Integration with Other Tools
bash
# Pipe to httpx for additional probing
node bin/subkamuna.js example.com --only-live -s | httpx -silent

# Use with nuclei for vulnerability scanning
node bin/subkamuna.js example.com --only-live -s | nuclei -t cves/

# Use with gau for URL discovery
node bin/subkamuna.js example.com --only-live -s | gau

# Use with katana for crawling
```bash
node bin/subkamuna.js example.com --only-live -s | katana
```
## Troubleshooting

Common Issues and Solutions
Issue	Cause	Solution
Cannot find module	Missing dependencies	Run npm install
Subfinder not found	Subfinder not installed	Tool uses DNS brute force automatically
No results found	DNS issues or incorrect domain	Check domain spelling, increase timeout -to 10
Rate limiting	Too many requests	Reduce threads -t 10, increase timeout -to 10
Connection timeout	Slow network	Increase timeout -to 15
Unicode display issues	Console encoding	Run chcp 65001 (Windows)
EACCESS errors	Permission denied	Run as Administrator
Empty results	Firewall blocking	Check firewall settings
Performance Optimization
```bash

#  Fast scanning (home network)
node bin/subkamuna.js example.com -t 100 -to 2

#  Stable scanning (corporate network)
node bin/subkamuna.js example.com -t 20 -to 10

#  Large domains (1000+ subdomains)
node bin/subkamuna.js example.com -t 200 -to 3

#  Stealth scanning
node bin/subkamuna.js example.com -t 5 -to 15

#  Maximum discovery
node bin/subkamuna.js example.com -t 150 -to 5 --scan-files --scan-folders
```
Debug Mode
```bash
# Run with verbose output
node bin/subkamuna.js example.com -v

# Check Node.js version
node --version

# List installed packages
npm list --depth=0

# Clear cache and reinstall
rmdir /s node_modules
npm install

# Test DNS resolution

nslookup example.com
```
❓ FAQ
Q: Do I need Subfinder installed?
A: No! SubKamuna works perfectly without Subfinder. It will automatically fall back to DNS brute force with a 200+ wordlist.

Q: How long does a scan take?
A: Depends on domain size and thread count:

Small domain (50 subdomains): 10-30 seconds

Medium domain (500 subdomains): 1-2 minutes

Large domain (5000+ subdomains): 5-10 minutes

Q: Can I scan multiple domains at once?
A: Yes! Use the -l option with a file containing one domain per line.

Q: Where are results saved?
A: Results are saved in the results/ folder in multiple formats (TXT, JSON, CSV, HTML).

Q: Is this tool free?
A: Yes! SubKamuna is completely free and open-source under MIT license.

Q: Does it work on Linux/Mac?
A: Yes! SubKamuna works on Windows, Linux, and macOS.

Q: Can I use my own wordlist?
A: Yes! Modify the wordlist array in lib/subfinder.js or create a custom wordlist file.

Q: How to avoid rate limiting?
A: Reduce threads with -t 10 and increase timeout with -to 10.

Q: What's the difference between --only-live and regular scan?
A: Regular scan shows all discovered subdomains. --only-live filters to only those responding to HTTP/HTTPS.

Q: Can I schedule automatic scans?
A: Yes! Use Windows Task Scheduler or cron jobs with the --real-report option.

Q: How accurate is technology detection?
A: Very accurate! Uses multiple patterns including headers, HTML, and JavaScript analysis.

Q: Does it support wildcard subdomains?
A: Yes, but results may include wildcard entries. Manual verification recommended.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

text
MIT License

Copyright (c) 2026 SubKamuna

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions...

Full license text in LICENSE file.

🙏 Acknowledgments
ProjectDiscovery - For Subfinder and other amazing tools

All Contributors - For testing and feedback

Security Community - For inspiration and use cases

📞 Support & Contact
[Issues](https://github.com/menmengleap/sub-kamuna/issues)

Documentation: GitHub Wiki

Email: menmengleapx1@gmail.com

Telegram: @neonsecxx

⭐ Show Your Support
If you find SubKamuna useful, please consider:

 Starring the repository on GitHub

 Reporting issues and bugs

 Suggesting new features

 Contributing code

 Sharing with others

# Show your support
echo " Star SubKamuna on GitHub!"
echo " Report issues to help improve"
echo " Contribute code to make it better"

##  Quick Reference Card
# Basic Scan
```
node bin/subkamuna.js example.com
```
# Live Only
```
node bin/subkamuna.js example.com --only-live
```
# Full Recon
```
node bin/subkamuna.js example.com --scan-files --scan-folders --tech-detect --real-report
```
# Multi-Domain
```
node bin/subkamuna.js -l domains.txt --only-live
```
# Fast Scan
```
node bin/subkamuna.js example.com -t 100 -to 2
```
# Silent Mode (Pipeline)
```
node bin/subkamuna.js example.com --only-live -s
```
# Verbose Mode
```
node bin/subkamuna.js example.com -v
```
# Help
```
node bin/subkamuna.js --help
```
Built with ❤️ for the security community

