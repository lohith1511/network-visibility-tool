#!/usr/bin/env python3
"""
Safe Internal Network Reconnaissance & Asset Inventory Toolkit
GUI Interface

ETHICAL USE DISCLAIMER:
This tool is designed for AUTHORIZED internal network scanning ONLY.
Use only on networks you own or have explicit written permission to scan.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
from datetime import datetime
from recon import NetworkRecon


class NetworkReconGUI:
    """GUI application for safe network reconnaissance"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Safe Network Reconnaissance & Asset Inventory Toolkit")
        self.root.geometry("1000x700")
        
        # Add ethical disclaimer
        self.show_disclaimer()
        
        self.recon = NetworkRecon()
        self.scanning = False
        
        self.create_widgets()
        self.load_hosts()
    
    def show_disclaimer(self):
        """Show ethical use disclaimer"""
        disclaimer = """ETHICAL USE DISCLAIMER

This tool is for AUTHORIZED internal network scanning ONLY.

✓ Use only on networks you own
✓ Use only with explicit written permission
✓ Use only in authorized lab environments

✗ DO NOT scan networks without permission
✗ DO NOT perform unauthorized reconnaissance
✗ DO NOT violate any laws or regulations

By using this tool, you agree to use it ethically and legally."""
        
        messagebox.showinfo("Ethical Use Disclaimer", disclaimer)
    
    def create_widgets(self):
        """Create GUI widgets"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title and disclaimer
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        title_label = ttk.Label(title_frame, 
                               text="Safe Network Reconnaissance & Asset Inventory", 
                               font=('Arial', 14, 'bold'))
        title_label.pack(side=tk.LEFT)
        
        disclaimer_label = ttk.Label(title_frame, 
                                    text="⚠ Authorized Use Only", 
                                    foreground='red',
                                    font=('Arial', 9))
        disclaimer_label.pack(side=tk.RIGHT)
        
        # Network input section
        input_frame = ttk.LabelFrame(main_frame, text="Network Scan Configuration", padding="10")
        input_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        input_frame.columnconfigure(1, weight=1)
        
        ttk.Label(input_frame, text="Network CIDR:").grid(row=0, column=0, sticky=tk.W, padx=5)
        
        entry_frame = ttk.Frame(input_frame)
        entry_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        entry_frame.columnconfigure(0, weight=1)
        
        self.network_var = tk.StringVar(value="192.168.1.0/24")
        network_entry = ttk.Entry(entry_frame, textvariable=self.network_var, width=30)
        network_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        self.scan_button = ttk.Button(entry_frame, text="Start Safe Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=1)
        
        # Info label
        info_label = ttk.Label(input_frame, 
                              text="Safe ports: 22, 80, 443 | Discovery: ARP + Nmap (-sn -T2)", 
                              font=('Arial', 8),
                              foreground='gray')
        info_label.grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Status label
        self.status_label = ttk.Label(main_frame, text="Ready", foreground='green')
        self.status_label.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Asset Inventory", padding="5")
        results_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Treeview for hosts with risk level
        columns = ('IP Address', 'Hostname', 'Status', 'Open Ports', 'OS Info', 'Risk Level', 'Discovery')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=12)
        
        # Configure column widths and headings
        column_widths = {
            'IP Address': 120,
            'Hostname': 150,
            'Status': 80,
            'Open Ports': 100,
            'OS Info': 150,
            'Risk Level': 100,
            'Discovery': 100
        }
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=column_widths.get(col, 100))
        
        # Add color tags for risk levels
        self.tree.tag_configure('LOW', background='#d4edda')
        self.tree.tag_configure('MEDIUM', background='#fff3cd')
        self.tree.tag_configure('HIGH', background='#f8d7da')
        
        scrollbar_y = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Log output
        log_frame = ttk.LabelFrame(main_frame, text="Scan Log", padding="5")
        log_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=6, wrap=tk.WORD, font=('Courier', 9))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="🔄 Refresh", command=self.load_hosts).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📄 Export Markdown", command=self.export_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📊 Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🗑️ Clear Database", command=self.clear_database).pack(side=tk.LEFT, padx=5)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="5")
        stats_frame.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.stats_label = ttk.Label(stats_frame, text="Total Hosts: 0 | Risk: LOW: 0, MEDIUM: 0, HIGH: 0")
        self.stats_label.pack()
    
    def log(self, message: str):
        """Add message to log with timestamp"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def update_status(self, message: str, color: str = 'black'):
        """Update status label"""
        self.status_label.config(text=message, foreground=color)
        self.root.update_idletasks()
    
    def start_scan(self):
        """Start network scan in separate thread"""
        if self.scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running!")
            return
        
        network = self.network_var.get().strip()
        if not network:
            messagebox.showerror("Error", "Please enter a network address!")
            return
        
        # Validate CIDR format
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            messagebox.showerror("Error", "Invalid network CIDR format!\nExample: 192.168.1.0/24")
            return
        
        self.scanning = True
        self.scan_button.config(state='disabled')
        self.progress.start()
        self.update_status("Scanning...", 'blue')
        self.log(f"Starting safe scan of {network}...")
        self.log("Using passive ARP discovery + active Nmap ping scan")
        self.log("Port scanning limited to: 22, 80, 443")
        
        # Run scan in separate thread
        thread = threading.Thread(target=self.run_scan, args=(network,))
        thread.daemon = True
        thread.start()
    
    def run_scan(self, network: str):
        """Run the actual scan"""
        try:
            results = self.recon.scan_network(network)
            self.root.after(0, self.scan_complete, results)
        except Exception as e:
            self.root.after(0, self.scan_error, str(e))
    
    def scan_complete(self, results):
        """Handle scan completion"""
        self.scanning = False
        self.scan_button.config(state='normal')
        self.progress.stop()
        self.update_status(f"Scan complete! Found {len(results)} hosts", 'green')
        self.log(f"Scan complete! Found {len(results)} active hosts.")
        
        # Calculate statistics
        risk_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
        for host in results:
            risk = host.get('risk_level', 'LOW')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        self.log(f"Risk distribution: LOW={risk_counts['LOW']}, MEDIUM={risk_counts['MEDIUM']}, HIGH={risk_counts['HIGH']}")
        
        self.load_hosts()
        messagebox.showinfo("Scan Complete", 
                          f"Found {len(results)} active hosts!\n\n"
                          f"Risk Levels:\n"
                          f"  LOW: {risk_counts['LOW']}\n"
                          f"  MEDIUM: {risk_counts['MEDIUM']}\n"
                          f"  HIGH: {risk_counts['HIGH']}")
    
    def scan_error(self, error: str):
        """Handle scan error"""
        self.scanning = False
        self.scan_button.config(state='normal')
        self.progress.stop()
        self.update_status("Scan error occurred", 'red')
        self.log(f"Error: {error}")
        messagebox.showerror("Scan Error", f"An error occurred:\n{error}")
    
    def load_hosts(self):
        """Load hosts from database"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Load hosts
        hosts = self.recon.get_all_hosts()
        
        risk_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
        
        for host in hosts:
            ports_str = ', '.join(map(str, host['ports'])) if host['ports'] else 'None'
            risk_level = host.get('risk_level', 'LOW')
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
            
            item = self.tree.insert('', tk.END, values=(
                host['ip'],
                host.get('hostname', 'N/A'),
                host.get('status', 'unknown'),
                ports_str,
                host.get('os_info', 'N/A'),
                risk_level,
                host.get('discovery_method', 'Unknown')
            ), tags=(risk_level,))
        
        # Update statistics
        total = len(hosts)
        stats_text = f"Total Hosts: {total} | Risk: LOW: {risk_counts['LOW']}, MEDIUM: {risk_counts['MEDIUM']}, HIGH: {risk_counts['HIGH']}"
        self.stats_label.config(text=stats_text)
        
        self.log(f"Loaded {len(hosts)} hosts from database.")
    
    def export_report(self):
        """Export report to markdown"""
        try:
            hosts = self.recon.get_all_hosts()
            if not hosts:
                messagebox.showwarning("No Data", "No hosts in database to export.")
                return
            
            report_path = "reports/report.md"
            
            # Create reports directory if it doesn't exist
            import os
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
            
            with open(report_path, 'w') as f:
                f.write("# Network Reconnaissance Report\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Total Hosts Found:** {len(hosts)}\n\n")
                
                # Risk summary
                risk_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
                for host in hosts:
                    risk = host.get('risk_level', 'LOW')
                    risk_counts[risk] = risk_counts.get(risk, 0) + 1
                
                f.write("## Risk Level Summary\n\n")
                f.write(f"- **LOW:** {risk_counts['LOW']}\n")
                f.write(f"- **MEDIUM:** {risk_counts['MEDIUM']}\n")
                f.write(f"- **HIGH:** {risk_counts['HIGH']}\n\n")
                
                f.write("## Hosts\n\n")
                
                for host in hosts:
                    f.write(f"### {host['ip']}\n\n")
                    f.write(f"- **Hostname:** {host.get('hostname', 'N/A')}\n")
                    f.write(f"- **Status:** {host.get('status', 'unknown')}\n")
                    f.write(f"- **Open Ports:** {', '.join(map(str, host['ports'])) if host['ports'] else 'None'}\n")
                    f.write(f"- **OS Info:** {host.get('os_info', 'N/A')}\n")
                    f.write(f"- **Risk Level:** {host.get('risk_level', 'LOW')}\n")
                    f.write(f"- **Discovery Method:** {host.get('discovery_method', 'Unknown')}\n")
                    f.write(f"- **Last Seen:** {host.get('last_seen', 'N/A')}\n\n")
            
            self.log(f"Report exported to {report_path}")
            messagebox.showinfo("Export Complete", f"Markdown report exported to:\n{report_path}")
        except Exception as e:
            self.log(f"Export error: {e}")
            messagebox.showerror("Export Error", f"Failed to export report:\n{e}")
    
    def export_csv(self):
        """Export inventory to CSV"""
        try:
            hosts = self.recon.get_all_hosts()
            if not hosts:
                messagebox.showwarning("No Data", "No hosts in database to export.")
                return
            
            # Ask user for file location
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile="inventory.csv",
                title="Save CSV Inventory"
            )
            
            if filename:
                if self.recon.export_to_csv(filename):
                    self.log(f"CSV exported to {filename}")
                    messagebox.showinfo("Export Complete", f"CSV inventory exported to:\n{filename}")
                else:
                    messagebox.showerror("Export Error", "Failed to export CSV file.")
        except Exception as e:
            self.log(f"CSV export error: {e}")
            messagebox.showerror("Export Error", f"Failed to export CSV:\n{e}")
    
    def clear_database(self):
        """Clear the database"""
        if messagebox.askyesno("Confirm", 
                               "Are you sure you want to clear the database?\n\n"
                               "This will delete all stored host information."):
            try:
                import sqlite3
                conn = sqlite3.connect(self.recon.db_path)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM hosts')
                cursor.execute('DELETE FROM scans')
                conn.commit()
                conn.close()
                self.load_hosts()
                self.log("Database cleared.")
                messagebox.showinfo("Success", "Database cleared successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear database:\n{e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkReconGUI(root)
    root.mainloop()
