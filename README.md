# Safe Network Reconnaissance Tool

A safe and ethical network reconnaissance tool for discovering and inventorying devices on your network.

## Features

- **Network Scanning**: Scan IP ranges to discover active hosts
- **Port Scanning**: Identify open ports on discovered hosts
- **Hostname Resolution**: Automatically resolve IP addresses to hostnames
- **Database Storage**: SQLite database for persistent inventory
- **GUI Interface**: User-friendly graphical interface
- **Automation**: Shell script and N8N workflow for scheduled scans
- **Reporting**: Generate markdown reports of scan results

## Requirements

- Python 3.7+
- tkinter (usually included with Python)
- Network access to target network

## Installation

1. Clone or download this repository
2. Install Python dependencies (if any):
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Command Line Interface

Basic usage:
```bash
python recon.py 192.168.1.0/24
```

### Graphical User Interface

Launch the GUI:
```bash
python gui.py
```

Features:
- Enter network CIDR notation (e.g., 192.168.1.0/24)
- Click "Start Scan" to begin scanning
- View results in the table
- Export reports to markdown
- Clear database if needed

### Shell Script

Run automated scan:
```bash
chmod +x scan.sh
./scan.sh 192.168.1.0/24
```

The script will:
- Scan the specified network
- Generate a timestamped report
- Save results to `reports/` directory

### N8N Workflow

1. Import `n8n/workflow.json` into your N8N instance
2. Configure the nodes:
   - Set your Telegram chat ID (if using notifications)
   - Configure Notion database (if using Notion integration)
3. Enable the workflow for automated daily scans

## Project Structure

```
safe-network-recon/
├── recon.py          # Main scanning module
├── gui.py            # Graphical user interface
├── scan.sh           # Shell script for automation
├── inventory.db      # SQLite database
├── reports/          # Generated reports
│   └── report.md     # Report template
├── n8n/              # N8N workflow
│   └── workflow.json # Automation workflow
└── README.md         # This file
```

## Database Schema

### hosts table
- `id`: Primary key
- `ip_address`: IP address (unique)
- `hostname`: Resolved hostname
- `status`: Host status (up/down)
- `ports`: JSON array of open ports
- `os_info`: Operating system information (future)
- `last_seen`: Last scan timestamp
- `created_at`: Record creation timestamp

### scans table
- `id`: Primary key
- `target`: Network target scanned
- `scan_type`: Type of scan performed
- `status`: Scan status
- `results`: JSON results
- `created_at`: Scan timestamp

## Ethical Use

**IMPORTANT**: This tool is intended for:
- Scanning networks you own
- Networks where you have explicit written permission
- Educational purposes in controlled environments

**DO NOT USE** this tool to:
- Scan networks without permission
- Perform unauthorized reconnaissance
- Violate any laws or regulations

Always ensure you have proper authorization before scanning any network.

## Limitations

- Port scanning may be slow on large networks
- Some hosts may not respond to ping but still be active
- Firewall rules may affect scan results
- Currently optimized for /24 networks in shell script

## Future Enhancements

- [ ] OS fingerprinting
- [ ] Service version detection
- [ ] Vulnerability scanning
- [ ] Web interface
- [ ] Email notifications
- [ ] Export to multiple formats (CSV, JSON, XML)
- [ ] Advanced filtering and search
- [ ] Network topology mapping

## License

This project is provided as-is for educational and authorized network administration purposes.

## Contributing

Contributions are welcome! Please ensure any changes maintain the ethical use principles of this tool.

## Support

For issues or questions, please check the code comments or create an issue in the repository.

