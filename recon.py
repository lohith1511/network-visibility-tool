#!/usr/bin/env python3
"""
Safe Internal Network Reconnaissance & Asset Inventory Toolkit
Main scanning and discovery module

ETHICAL USE DISCLAIMER:
This tool is designed for AUTHORIZED internal network scanning ONLY.
Use only on networks you own or have explicit written permission to scan.
Unauthorized scanning is illegal and unethical.
"""

import os
import sys
import socket
import subprocess
import ipaddress
import json
import sqlite3
import csv
from datetime import datetime
from typing import List, Dict, Optional, Set

# Try to import optional dependencies
try:
    from scapy.all import ARP, Ether, srp, get_if_addr, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Passive ARP discovery disabled.")
    print("Install with: pip install scapy")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Warning: python-nmap not available. Nmap integration disabled.")
    print("Install with: pip install python-nmap")
    print("Also ensure Nmap is installed: sudo apt-get install nmap")


class NetworkRecon:
    """
    Main network reconnaissance class implementing safe scanning practices.
    
    SAFE SCANNING RULES:
    - Passive discovery FIRST using ARP (Scapy)
    - Active discovery using: nmap -sn -T2 (safe ping scan)
    - Port scanning LIMITED to: 22, 80, 443
    - NO aggressive flags
    - NO vulnerability scripts
    - NO full port scans
    """
    
    # Safe port list - LIMITED to essential ports only
    SAFE_PORTS = [22, 80, 443]
    
    def __init__(self, db_path: str = "inventory.db"):
        """Initialize with database path"""
        self.db_path = db_path
        self.init_database()
        
        # Initialize Nmap scanner if available
        if NMAP_AVAILABLE:
            try:
                self.nm = nmap.PortScanner()
            except Exception as e:
                print(f"Warning: Could not initialize Nmap scanner: {e}")
                self.nm = None
        else:
            self.nm = None
    
    def init_database(self):
        """Initialize SQLite database with enhanced schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Enhanced hosts table with risk level
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                hostname TEXT,
                status TEXT,
                ports TEXT,
                os_info TEXT,
                risk_level TEXT,
                discovery_method TEXT,
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Enhanced scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                scan_type TEXT,
                status TEXT,
                hosts_found INTEGER,
                results TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def passive_arp_discovery(self, network: str) -> Set[str]:
        """
        Passive host discovery using ARP requests (Scapy).
        This is the SAFEST method as it only queries the local ARP table.
        
        Args:
            network: Network CIDR (e.g., "192.168.1.0/24")
            
        Returns:
            Set of discovered IP addresses
        """
        discovered_hosts = set()
        
        if not SCAPY_AVAILABLE:
            print("Scapy not available. Skipping passive ARP discovery.")
            return discovered_hosts
        
        try:
            print(f"[PASSIVE] Starting ARP discovery for {network}...")
            
            # Create ARP request packet
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send packet and receive responses (timeout=2 seconds, verbose=0)
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=0)[0]
            
            # Extract IP addresses from responses
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                discovered_hosts.add(ip)
                print(f"[PASSIVE] Found: {ip} ({mac})")
            
            print(f"[PASSIVE] Discovered {len(discovered_hosts)} hosts via ARP")
            
        except Exception as e:
            print(f"[PASSIVE] Error during ARP discovery: {e}")
            print("Continuing with active discovery only...")
        
        return discovered_hosts
    
    def active_nmap_discovery(self, network: str) -> Set[str]:
        """
        Active host discovery using SAFE Nmap ping scan.
        Uses: nmap -sn -T2 (safe, polite timing)
        
        Args:
            network: Network CIDR
            
        Returns:
            Set of discovered IP addresses
        """
        discovered_hosts = set()
        
        if not NMAP_AVAILABLE or self.nm is None:
            print("Nmap not available. Skipping active discovery.")
            return discovered_hosts
        
        try:
            print(f"[ACTIVE] Starting safe Nmap ping scan for {network}...")
            print("[ACTIVE] Using: nmap -sn -T2 (safe ping scan)")
            
            # SAFE Nmap scan: -sn (ping scan only), -T2 (polite timing)
            self.nm.scan(hosts=network, arguments='-sn -T2')
            
            # Extract discovered hosts
            for host in self.nm.all_hosts():
                discovered_hosts.add(host)
                print(f"[ACTIVE] Found: {host}")
            
            print(f"[ACTIVE] Discovered {len(discovered_hosts)} hosts via Nmap")
            
        except Exception as e:
            print(f"[ACTIVE] Error during Nmap scan: {e}")
            print("Falling back to basic ping scan...")
            # Fallback to basic ping
            return self.fallback_ping_scan(network)
        
        return discovered_hosts
    
    def fallback_ping_scan(self, network: str) -> Set[str]:
        """Fallback ping scan if Nmap is unavailable"""
        discovered_hosts = set()
        try:
            net = ipaddress.ip_network(network, strict=False)
            for ip in list(net.hosts())[:50]:  # Limit to first 50 for safety
                ip_str = str(ip)
                if self.ping_host(ip_str):
                    discovered_hosts.add(ip_str)
        except Exception as e:
            print(f"Fallback ping scan error: {e}")
        return discovered_hosts
    
    def ping_host(self, host: str) -> bool:
        """Check if host is reachable via ping"""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', host],
                                      capture_output=True, timeout=3)
            else:  # Unix/Linux
                result = subprocess.run(['ping', '-c', '1', '-W', '1', host],
                                      capture_output=True, timeout=3)
            return result.returncode == 0
        except Exception:
            return False
    
    def safe_port_scan(self, host: str) -> List[int]:
        """
        SAFE port scanning - LIMITED to ports 22, 80, 443 only.
        NO aggressive scanning, NO full port scans.
        
        Args:
            host: IP address to scan
            
        Returns:
            List of open ports
        """
        open_ports = []
        
        # Use Nmap if available for more reliable results
        if NMAP_AVAILABLE and self.nm is not None:
            try:
                # SAFE port scan: only specific ports, polite timing
                ports_str = ','.join(map(str, self.SAFE_PORTS))
                self.nm.scan(host, ports_str, arguments='-T2')
                
                if host in self.nm.all_hosts():
                    for port in self.nm[host].all_tcp():
                        if self.nm[host]['tcp'][port]['state'] == 'open':
                            open_ports.append(port)
            except Exception as e:
                print(f"  Nmap port scan error for {host}: {e}")
                # Fallback to socket-based scan
                open_ports = self.socket_port_scan(host)
        else:
            # Fallback to socket-based scan
            open_ports = self.socket_port_scan(host)
        
        return open_ports
    
    def socket_port_scan(self, host: str) -> List[int]:
        """Fallback socket-based port scan"""
        open_ports = []
        for port in self.SAFE_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            except Exception:
                continue
        return open_ports
    
    def resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP to hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None
    
    def lightweight_os_fingerprint(self, host: str, open_ports: List[int]) -> Optional[str]:
        """
        Lightweight OS fingerprinting based on open ports and services.
        SAFE method - no aggressive probes.
        
        Args:
            host: IP address
            open_ports: List of open ports
            
        Returns:
            Estimated OS information or None
        """
        # Very basic OS hints based on port patterns
        # This is educational and not definitive
        if not open_ports:
            return None
        
        os_hints = []
        
        # SSH on 22 typically indicates Linux/Unix
        if 22 in open_ports:
            os_hints.append("Linux/Unix-like")
        
        # Windows RDP on 3389
        if 3389 in open_ports:
            os_hints.append("Windows")
        
        # Web services
        if 80 in open_ports or 443 in open_ports:
            os_hints.append("Web Server")
        
        if os_hints:
            return " / ".join(os_hints)
        
        return "Unknown"
    
    def calculate_risk_level(self, open_ports: List[int], hostname: Optional[str]) -> str:
        """
        Calculate risk level based on exposed services.
        
        Risk Levels:
        - LOW: Single or minimal service exposure (e.g., only port 80)
        - MEDIUM: Multiple services exposed (e.g., 22, 80, 443)
        - HIGH: Sensitive services or unusual patterns
        
        Args:
            open_ports: List of open ports
            hostname: Hostname (if available)
            
        Returns:
            Risk level string: "LOW", "MEDIUM", or "HIGH"
        """
        if not open_ports:
            return "LOW"
        
        port_count = len(open_ports)
        
        # HIGH risk indicators
        if port_count >= 3:
            return "HIGH"
        
        # SSH exposure (port 22) increases risk
        if 22 in open_ports and port_count >= 2:
            return "MEDIUM"
        
        # Multiple web services
        if 80 in open_ports and 443 in open_ports:
            return "MEDIUM"
        
        # Single service exposure
        if port_count == 1:
            return "LOW"
        
        # Default to MEDIUM for 2 ports
        return "MEDIUM"
    
    def scan_network(self, network: str) -> List[Dict]:
        """
        Main network scanning function.
        Implements passive + active discovery, then safe port scanning.
        
        Args:
            network: Network CIDR (e.g., "192.168.1.0/24")
            
        Returns:
            List of discovered hosts with metadata
        """
        print("\n" + "="*60)
        print("SAFE NETWORK RECONNAISSANCE SCAN")
        print("="*60)
        print(f"Target Network: {network}")
        print(f"Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60 + "\n")
        
        # Step 1: Passive ARP discovery
        passive_hosts = self.passive_arp_discovery(network)
        
        # Step 2: Active Nmap discovery
        active_hosts = self.active_nmap_discovery(network)
        
        # Step 3: Merge host lists (remove duplicates)
        all_hosts = passive_hosts.union(active_hosts)
        
        print(f"\n[MERGE] Total unique hosts discovered: {len(all_hosts)}")
        print(f"  - Passive (ARP): {len(passive_hosts)}")
        print(f"  - Active (Nmap): {len(active_hosts)}")
        
        if not all_hosts:
            print("\n[WARNING] No hosts discovered. Check network connectivity and permissions.")
            return []
        
        # Step 4: Safe port scanning on discovered hosts
        results = []
        print(f"\n[PORT SCAN] Starting safe port scan (ports: {self.SAFE_PORTS})...")
        
        for ip in sorted(all_hosts):
            print(f"\n[SCANNING] {ip}...")
            
            # Resolve hostname
            hostname = self.resolve_hostname(ip)
            if hostname:
                print(f"  Hostname: {hostname}")
            
            # Safe port scan
            open_ports = self.safe_port_scan(ip)
            print(f"  Open Ports: {open_ports if open_ports else 'None'}")
            
            # Lightweight OS fingerprinting
            os_info = self.lightweight_os_fingerprint(ip, open_ports)
            if os_info:
                print(f"  OS Info: {os_info}")
            
            # Calculate risk level
            risk_level = self.calculate_risk_level(open_ports, hostname)
            print(f"  Risk Level: {risk_level}")
            
            # Determine discovery method
            discovery_method = []
            if ip in passive_hosts:
                discovery_method.append("ARP")
            if ip in active_hosts:
                discovery_method.append("Nmap")
            
            result = {
                'ip': ip,
                'hostname': hostname,
                'status': 'up',
                'ports': open_ports,
                'os_info': os_info,
                'risk_level': risk_level,
                'discovery_method': ', '.join(discovery_method),
                'timestamp': datetime.now().isoformat()
            }
            results.append(result)
            self.save_host(result)
        
        # Save scan record
        self.save_scan_record(network, len(results))
        
        print("\n" + "="*60)
        print(f"SCAN COMPLETE: Found {len(results)} active hosts")
        print("="*60 + "\n")
        
        return results
    
    def save_host(self, host_data: Dict):
        """Save host information to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO hosts 
                (ip_address, hostname, status, ports, os_info, risk_level, 
                 discovery_method, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                host_data['ip'],
                host_data.get('hostname'),
                host_data.get('status', 'up'),
                json.dumps(host_data.get('ports', [])),
                host_data.get('os_info'),
                host_data.get('risk_level', 'LOW'),
                host_data.get('discovery_method', 'Unknown'),
                datetime.now().isoformat()
            ))
            conn.commit()
        except Exception as e:
            print(f"Error saving host: {e}")
        finally:
            conn.close()
    
    def save_scan_record(self, target: str, hosts_found: int):
        """Save scan metadata to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO scans 
                (target, scan_type, status, hosts_found, results)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                target,
                'safe_recon',
                'completed',
                hosts_found,
                json.dumps({'timestamp': datetime.now().isoformat()})
            ))
            conn.commit()
        except Exception as e:
            print(f"Error saving scan record: {e}")
        finally:
            conn.close()
    
    def get_all_hosts(self) -> List[Dict]:
        """Retrieve all hosts from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM hosts ORDER BY last_seen DESC')
        rows = cursor.fetchall()
        conn.close()
        
        hosts = []
        for row in rows:
            hosts.append({
                'id': row[0],
                'ip': row[1],
                'hostname': row[2],
                'status': row[3],
                'ports': json.loads(row[4]) if row[4] else [],
                'os_info': row[5],
                'risk_level': row[6] or 'LOW',
                'discovery_method': row[7] or 'Unknown',
                'last_seen': row[8],
                'created_at': row[9]
            })
        
        return hosts
    
    def export_to_csv(self, filename: str = "reports/inventory.csv") -> bool:
        """
        Export asset inventory to CSV format.
        
        Args:
            filename: Output CSV file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            hosts = self.get_all_hosts()
            
            # Create reports directory if it doesn't exist
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ['IP Address', 'Hostname', 'Status', 'Open Ports', 
                            'OS Info', 'Risk Level', 'Discovery Method', 'Last Seen']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for host in hosts:
                    writer.writerow({
                        'IP Address': host['ip'],
                        'Hostname': host.get('hostname', 'N/A'),
                        'Status': host.get('status', 'unknown'),
                        'Open Ports': ', '.join(map(str, host['ports'])) if host['ports'] else 'None',
                        'OS Info': host.get('os_info', 'N/A'),
                        'Risk Level': host.get('risk_level', 'LOW'),
                        'Discovery Method': host.get('discovery_method', 'Unknown'),
                        'Last Seen': host.get('last_seen', 'N/A')
                    })
            
            print(f"CSV export successful: {filename}")
            return True
            
        except Exception as e:
            print(f"CSV export error: {e}")
            return False


if __name__ == "__main__":
    print("\n" + "="*60)
    print("SAFE INTERNAL NETWORK RECONNAISSANCE TOOL")
    print("="*60)
    print("\nETHICAL USE DISCLAIMER:")
    print("This tool is for AUTHORIZED internal network scanning ONLY.")
    print("Use only on networks you own or have explicit permission to scan.")
    print("="*60 + "\n")
    
    recon = NetworkRecon()
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        results = recon.scan_network(target)
        
        if results:
            print(f"\n{'='*60}")
            print("SCAN SUMMARY")
            print(f"{'='*60}\n")
            print(f"Total Hosts: {len(results)}")
            
            # Risk level summary
            risk_counts = {}
            for host in results:
                risk = host.get('risk_level', 'LOW')
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
            
            print("\nRisk Level Distribution:")
            for risk, count in sorted(risk_counts.items()):
                print(f"  {risk}: {count}")
            
            print(f"\n{'='*60}\n")
            
            # Export to CSV
            csv_path = "reports/inventory.csv"
            if recon.export_to_csv(csv_path):
                print(f"Inventory exported to: {csv_path}")
        else:
            print("\nNo hosts discovered.")
    else:
        print("Usage: python recon.py <network_cidr>")
        print("Example: python recon.py 192.168.1.0/24")
        print("\nIMPORTANT: Only scan networks you own or have permission to scan!")
