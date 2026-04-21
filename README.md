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
cd sub-kamuna
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

