# Safe Internal Network Reconnaissance & Asset Inventory Toolkit

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Educational-green.svg)](LICENSE)
[![Ethical Use](https://img.shields.io/badge/Ethical-Use%20Only-red.svg)](README.md#ethical-use-disclaimer)

A comprehensive, **safe**, and **ethical** network reconnaissance tool designed for academic cybersecurity labs, CEH/SOC training, and authorized internal network assessments.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Ethical Use Disclaimer](#ethical-use-disclaimer)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Architecture](#architecture)
- [Safe Scanning Practices](#safe-scanning-practices)
- [Database Schema](#database-schema)
- [Export Formats](#export-formats)
- [Automation](#automation)
- [Troubleshooting](#troubleshooting)
- [Academic Use](#academic-use)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

This toolkit provides a **safe** and **ethical** approach to internal network reconnaissance, designed specifically for:

- 🎓 **Academic Labs:** Cybersecurity coursework and research
- 🔐 **CEH/SOC Training:** Ethical hacking and security operations practice
- 📊 **Asset Inventory:** Network device discovery and documentation
- 🏢 **Authorized Assessments:** Internal network security audits

The tool implements **strict safe scanning practices** to ensure minimal network impact while providing comprehensive asset discovery and inventory capabilities.

---

## ✨ Features

### Core Capabilities

- **🔍 Passive Discovery:** ARP-based host discovery using Scapy (least intrusive)
- **🌐 Active Discovery:** Safe Nmap ping scan (`-sn -T2`) for network-wide discovery
- **🔌 Limited Port Scanning:** Safe scanning of essential ports (22, 80, 443)
- **🏷️ Risk Assessment:** Automatic risk level tagging (LOW/MEDIUM/HIGH)
- **💾 Persistent Storage:** SQLite database for asset inventory
- **🖥️ Desktop GUI:** User-friendly Tkinter interface
- **📊 Multiple Exports:** Markdown reports and CSV inventory
- **🤖 Automation Ready:** Bash scripts and N8N workflow integration

### Safety Features

- ✅ Passive discovery attempted first
- ✅ Safe Nmap flags only (`-sn -T2`)
- ✅ Limited port scanning scope
- ✅ No aggressive timing
- ✅ No vulnerability scripts
- ✅ No full port scans
- ✅ Clear ethical disclaimers

---

## ⚠️ Ethical Use Disclaimer

**CRITICAL:** This tool is designed for **AUTHORIZED internal network scanning ONLY**.

### ✅ Authorized Use

- Networks you own or manage
- Networks with **explicit written permission**
- Authorized security assessments
- Educational labs with proper authorization
- Internal network documentation

### ❌ Prohibited Use

- Scanning networks without permission
- Unauthorized reconnaissance
- Violating any laws or regulations
- Scanning external networks
- Any malicious or illegal activity

**By using this tool, you agree to use it ethically and legally. Unauthorized scanning is illegal and unethical.**

---

## 📦 Requirements

### System Requirements

- **OS:** Linux (Kali Linux, Ubuntu) or macOS
- **Python:** 3.7 or higher
- **Network Access:** Access to target network segment
- **Permissions:** Root/sudo may be required for ARP discovery

### Python Dependencies

Install via pip:

```bash
pip install -r requirements.txt
```

**Required packages:**
- `scapy>=2.5.0` - Passive ARP discovery
- `python-nmap>=0.7.1` - Nmap integration

### System Dependencies

**Nmap** must be installed separately:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install nmap

# Kali Linux (usually pre-installed)
# Verify with: nmap --version

# macOS
brew install nmap
```

---

## 🚀 Installation

### Step 1: Clone Repository

```bash
git clone <repository-url>
cd safe-network-recon
```

### Step 2: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Install System Dependencies

```bash
# Install Nmap
sudo apt-get install nmap  # Ubuntu/Debian
# or
brew install nmap  # macOS
```

### Step 4: Verify Installation

```bash
# Check Python version
python3 --version  # Should be 3.7+

# Check Nmap
nmap --version

# Test Python imports
python3 -c "import scapy; import nmap; print('All dependencies installed!')"
```

### Step 5: Make Scripts Executable

```bash
chmod +x scan.sh
```

---

## 💻 Usage

### Command Line Interface

**Basic usage:**

```bash
python3 recon.py 192.168.1.0/24
```

**What it does:**
1. Performs passive ARP discovery
2. Performs active Nmap ping scan (`-sn -T2`)
3. Merges discovered hosts
4. Scans ports 22, 80, 443 on discovered hosts
5. Calculates risk levels
6. Stores results in SQLite database
7. Exports CSV inventory

**Output:**
- Console output with scan progress
- SQLite database: `inventory.db`
- CSV export: `reports/inventory.csv`

### Graphical User Interface

**Launch GUI:**

```bash
python3 gui.py
```

**GUI Features:**
- Network CIDR input
- Start scan button
- Real-time scan progress
- Asset inventory table with risk levels
- Export to Markdown and CSV
- Database management
- Statistics display

**GUI Workflow:**
1. Enter network CIDR (e.g., `192.168.1.0/24`)
2. Click "Start Safe Scan"
3. Monitor progress in log window
4. View results in asset inventory table
5. Export reports as needed

### Bash Automation Script

**Run automated scan:**

```bash
./scan.sh 192.168.1.0/24
```

**What it does:**
- Runs Python scanner
- Generates timestamped Markdown report
- Exports CSV inventory
- Logs all activity

**Output files:**
- `reports/scan_YYYYMMDD_HHMMSS.md` - Timestamped report
- `reports/inventory_YYYYMMDD_HHMMSS.csv` - Timestamped CSV

### N8N Workflow Automation

**Setup:**
1. Import `n8n/workflow.json` into your N8N instance
2. Configure schedule trigger (e.g., daily at 2 AM)
3. Set network target
4. Configure notifications (optional)
5. Enable workflow

**Workflow includes:**
- Scheduled trigger (cron)
- Execute scan script
- Read report
- Optional notifications (Telegram, email, etc.)

---

## 📁 Project Structure

```
safe-network-recon/
├── recon.py              # Main scanning module
├── gui.py                # Tkinter GUI interface
├── scan.sh               # Bash automation script
├── requirements.txt      # Python dependencies
├── inventory.db          # SQLite asset inventory (created on first run)
├── README.md             # This file
├── reports/              # Generated reports
│   ├── report.md         # Security report template
│   ├── inventory.csv     # CSV export (generated)
│   └── scan_*.md         # Timestamped scan reports
└── n8n/                  # N8N automation
    └── workflow.json      # N8N workflow configuration
```

---

## 🏗️ Architecture

### Scanning Workflow

```
1. Passive Discovery (Scapy ARP)
   └─> Query local ARP table
   └─> Discover hosts on network segment

2. Active Discovery (Nmap -sn -T2)
   └─> Safe ping scan
   └─> Discover additional hosts

3. Merge Results
   └─> Combine passive + active discoveries
   └─> Remove duplicates

4. Port Scanning (Limited: 22, 80, 443)
   └─> Safe port scan on discovered hosts
   └─> Identify open services

5. Asset Enrichment
   └─> Hostname resolution
   └─> Lightweight OS fingerprinting
   └─> Risk level calculation

6. Storage & Export
   └─> Save to SQLite database
   └─> Export to CSV
   └─> Generate Markdown report
```

### Component Overview

**recon.py:**
- `NetworkRecon` class - Main scanning logic
- Passive ARP discovery
- Active Nmap discovery
- Safe port scanning
- Risk assessment
- Database operations
- CSV export

**gui.py:**
- `NetworkReconGUI` class - Tkinter interface
- Network input and validation
- Scan execution (threaded)
- Results display with risk coloring
- Export functionality
- Statistics display

**scan.sh:**
- Bash automation wrapper
- Dependency checking
- Report generation
- CSV export coordination

---

## 🛡️ Safe Scanning Practices

### Implemented Safety Measures

1. **Passive First:** ARP discovery attempted before active scanning
2. **Safe Nmap Flags:** Only `-sn -T2` (ping scan, polite timing)
3. **Limited Ports:** Only 22, 80, 443 scanned
4. **No Aggressive Options:** No `-A`, `-sV`, `-sC` flags
5. **No Scripts:** No NSE vulnerability scripts
6. **Polite Timing:** T2 timing template (polite)

### What We DON'T Do

- ❌ Full port scans (1-65535)
- ❌ Aggressive timing (`-T4`, `-T5`)
- ❌ Service version detection (`-sV`)
- ❌ OS detection (`-O`)
- ❌ Vulnerability scripts (`--script vuln`)
- ❌ Stealth scans (`-sS`, `-sF`)
- ❌ UDP scans

---

## 🗄️ Database Schema

### hosts Table

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| ip_address | TEXT | IP address (unique) |
| hostname | TEXT | Resolved hostname |
| status | TEXT | Host status (up/down) |
| ports | TEXT | JSON array of open ports |
| os_info | TEXT | OS information hints |
| risk_level | TEXT | Risk level (LOW/MEDIUM/HIGH) |
| discovery_method | TEXT | How host was discovered |
| last_seen | TIMESTAMP | Last scan timestamp |
| created_at | TIMESTAMP | Record creation time |

### scans Table

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| target | TEXT | Network CIDR scanned |
| scan_type | TEXT | Type of scan performed |
| status | TEXT | Scan status |
| hosts_found | INTEGER | Number of hosts discovered |
| results | TEXT | JSON scan results |
| created_at | TIMESTAMP | Scan timestamp |

---

## 📊 Export Formats

### CSV Export

**File:** `reports/inventory.csv`

**Columns:**
- IP Address
- Hostname
- Status
- Open Ports
- OS Info
- Risk Level
- Discovery Method
- Last Seen

**Usage:**
```bash
# Via CLI (automatic after scan)
python3 recon.py 192.168.1.0/24

# Via GUI
# Click "Export CSV" button

# Via Python
from recon import NetworkRecon
recon = NetworkRecon()
recon.export_to_csv("reports/inventory.csv")
```

### Markdown Report

**File:** `reports/report.md`

**Contents:**
- Executive summary
- Risk level distribution
- Detailed host information
- Recommendations
- Methodology

**Usage:**
```bash
# Via GUI
# Click "Export Markdown" button

# Reports are also generated by scan.sh
./scan.sh 192.168.1.0/24
```

---

## 🤖 Automation

### Scheduled Scanning

**Option 1: Cron Job**

```bash
# Edit crontab
crontab -e

# Add daily scan at 2 AM
0 2 * * * cd /path/to/safe-network-recon && ./scan.sh 192.168.1.0/24
```

**Option 2: N8N Workflow**

1. Import `n8n/workflow.json`
2. Configure schedule trigger
3. Set network target
4. Enable workflow

**Option 3: Systemd Timer** (Linux)

Create `/etc/systemd/system/network-scan.service`:
```ini
[Unit]
Description=Network Reconnaissance Scan

[Service]
Type=oneshot
ExecStart=/path/to/safe-network-recon/scan.sh 192.168.1.0/24
```

Create `/etc/systemd/system/network-scan.timer`:
```ini
[Unit]
Description=Daily Network Scan

[Timer]
OnCalendar=daily
OnCalendar=02:00

[Install]
WantedBy=timers.target
```

Enable:
```bash
sudo systemctl enable network-scan.timer
sudo systemctl start network-scan.timer
```

---

## 🔧 Troubleshooting

### Common Issues

**Issue: "Scapy not available"**
```bash
pip install scapy
# Note: May require root for some operations
```

**Issue: "Nmap not found"**
```bash
sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS
```

**Issue: "Permission denied" for ARP**
```bash
# ARP discovery may require root/sudo
sudo python3 recon.py 192.168.1.0/24
```

**Issue: "No hosts discovered"**
- Check network connectivity
- Verify network CIDR format
- Ensure you're on the target network
- Check firewall rules

**Issue: "GUI not starting"**
```bash
# Install tkinter (if not included)
sudo apt-get install python3-tk  # Ubuntu/Debian
```

### Debug Mode

Enable verbose output:
```bash
python3 recon.py 192.168.1.0/24 2>&1 | tee scan.log
```

---

## 🎓 Academic Use

This project is suitable for:

### Coursework
- Network security courses
- Ethical hacking (CEH)
- Security operations (SOC)
- Penetration testing labs

### Learning Objectives
- Network reconnaissance techniques
- Asset inventory management
- Risk assessment
- Security tool development
- Ethical hacking practices

### Project Expo
- Demonstrates full-stack Python development
- Shows cybersecurity best practices
- Includes GUI and automation
- Professional documentation

### GitHub Portfolio
- Clean, well-documented code
- Professional README
- Ethical use focus
- Real-world application

---

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. ✅ All changes maintain ethical use principles
2. ✅ Safe scanning practices are preserved
3. ✅ Code follows existing style
4. ✅ Documentation is updated
5. ✅ Tests are added for new features

**Guidelines:**
- Use clear, descriptive commit messages
- Add comments for complex logic
- Update README for new features
- Maintain backward compatibility

---

## 📄 License

This project is provided for **educational and authorized network administration purposes**.

**Terms:**
- Free to use for educational purposes
- Must be used ethically and legally
- No warranty provided
- Author not responsible for misuse

---

## 📞 Support

**For Issues:**
- Check [Troubleshooting](#troubleshooting) section
- Review code comments
- Check error messages carefully

**For Questions:**
- Review documentation
- Check ethical use guidelines
- Consult with instructor/advisor

---

## 🙏 Acknowledgments

- Built for academic cybersecurity education
- Designed with safety and ethics in mind
- Suitable for CEH/SOC training
- GitHub portfolio ready

---

## 📝 Changelog

### Version 1.0.0
- Initial release
- Passive ARP discovery
- Safe Nmap integration
- Risk assessment
- GUI interface
- CSV/Markdown exports
- Automation scripts

---

**Remember:** Always ensure proper authorization before scanning any network. Use this tool responsibly and ethically.

**Happy (Safe) Scanning! 🔒**
