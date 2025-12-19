#!/usr/bin/env python3
"""
Network Reconnaissance Tool
Main scanning and discovery module
"""

import os
import socket
import subprocess
import ipaddress
import json
import sqlite3
from datetime import datetime
from typing import List, Dict, Optional


class NetworkRecon:
    """Main network reconnaissance class"""
    
    def __init__(self, db_path: str = "inventory.db"):
        """Initialize with database path"""
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                hostname TEXT,
                status TEXT,
                ports TEXT,
                os_info TEXT,
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                scan_type TEXT,
                status TEXT,
                results TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def ping_host(self, host: str) -> bool:
        """Check if host is reachable"""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', host],
                                      capture_output=True, timeout=5)
            else:  # Unix/Linux
                result = subprocess.run(['ping', '-c', '1', '-W', '1', host],
                                      capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def scan_port(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def scan_ports(self, host: str, ports: List[int], timeout: float = 1.0) -> List[int]:
        """Scan multiple ports on a host"""
        open_ports = []
        for port in ports:
            if self.scan_port(host, port, timeout):
                open_ports.append(port)
        return open_ports
    
    def scan_common_ports(self, host: str) -> List[int]:
        """Scan common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3389]
        return self.scan_ports(host, common_ports)
    
    def resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP to hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None
    
    def scan_network(self, network: str) -> List[Dict]:
        """Scan a network range"""
        results = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            for ip in net.hosts():
                ip_str = str(ip)
                print(f"Scanning {ip_str}...")
                
                if self.ping_host(ip_str):
                    hostname = self.resolve_hostname(ip_str)
                    ports = self.scan_common_ports(ip_str)
                    
                    result = {
                        'ip': ip_str,
                        'hostname': hostname,
                        'status': 'up',
                        'ports': ports,
                        'timestamp': datetime.now().isoformat()
                    }
                    results.append(result)
                    self.save_host(result)
        except Exception as e:
            print(f"Error scanning network: {e}")
        
        return results
    
    def save_host(self, host_data: Dict):
        """Save host information to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO hosts 
                (ip_address, hostname, status, ports, last_seen)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                host_data['ip'],
                host_data.get('hostname'),
                host_data.get('status', 'up'),
                json.dumps(host_data.get('ports', [])),
                datetime.now().isoformat()
            ))
            conn.commit()
        except Exception as e:
            print(f"Error saving host: {e}")
        finally:
            conn.close()
    
    def get_all_hosts(self) -> List[Dict]:
        """Retrieve all hosts from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM hosts')
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
                'last_seen': row[6],
                'created_at': row[7]
            })
        
        return hosts


if __name__ == "__main__":
    import os
    import sys
    
    recon = NetworkRecon()
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"Scanning network: {target}")
        results = recon.scan_network(target)
        print(f"\nFound {len(results)} active hosts:")
        for host in results:
            print(f"  {host['ip']} - {host.get('hostname', 'N/A')} - Ports: {host['ports']}")
    else:
        print("Usage: python recon.py <network_cidr>")
        print("Example: python recon.py 192.168.1.0/24")

