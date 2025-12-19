#!/usr/bin/env python3
"""
GUI Interface for Network Reconnaissance Tool
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from recon import NetworkRecon


class NetworkReconGUI:
    """GUI application for network reconnaissance"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Safe Network Reconnaissance Tool")
        self.root.geometry("800x600")
        
        self.recon = NetworkRecon()
        self.scanning = False
        
        self.create_widgets()
        self.load_hosts()
    
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
        
        # Network input section
        ttk.Label(main_frame, text="Network to Scan:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        input_frame = ttk.Frame(main_frame)
        input_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        input_frame.columnconfigure(0, weight=1)
        
        self.network_var = tk.StringVar(value="192.168.1.0/24")
        network_entry = ttk.Entry(input_frame, textvariable=self.network_var, width=30)
        network_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        self.scan_button = ttk.Button(input_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=1)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="5")
        results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Treeview for hosts
        columns = ('IP Address', 'Hostname', 'Status', 'Open Ports')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Log output
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="5")
        log_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=5)
        
        ttk.Button(button_frame, text="Refresh", command=self.load_hosts).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Report", command=self.export_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Database", command=self.clear_database).pack(side=tk.LEFT, padx=5)
    
    def log(self, message: str):
        """Add message to log"""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
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
        
        self.scanning = True
        self.scan_button.config(state='disabled')
        self.progress.start()
        self.log(f"Starting scan of {network}...")
        
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
        self.log(f"Scan complete! Found {len(results)} active hosts.")
        self.load_hosts()
        messagebox.showinfo("Scan Complete", f"Found {len(results)} active hosts!")
    
    def scan_error(self, error: str):
        """Handle scan error"""
        self.scanning = False
        self.scan_button.config(state='normal')
        self.progress.stop()
        self.log(f"Error: {error}")
        messagebox.showerror("Scan Error", f"An error occurred: {error}")
    
    def load_hosts(self):
        """Load hosts from database"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Load hosts
        hosts = self.recon.get_all_hosts()
        for host in hosts:
            ports_str = ', '.join(map(str, host['ports'])) if host['ports'] else 'None'
            self.tree.insert('', tk.END, values=(
                host['ip'],
                host.get('hostname', 'N/A'),
                host.get('status', 'unknown'),
                ports_str
            ))
        
        self.log(f"Loaded {len(hosts)} hosts from database.")
    
    def export_report(self):
        """Export report to markdown"""
        try:
            hosts = self.recon.get_all_hosts()
            report_path = "reports/report.md"
            
            with open(report_path, 'w') as f:
                f.write("# Network Reconnaissance Report\n\n")
                f.write(f"Generated: {self.recon.get_all_hosts()[0]['created_at'] if hosts else 'N/A'}\n\n")
                f.write(f"Total Hosts Found: {len(hosts)}\n\n")
                f.write("## Hosts\n\n")
                
                for host in hosts:
                    f.write(f"### {host['ip']}\n")
                    f.write(f"- **Hostname:** {host.get('hostname', 'N/A')}\n")
                    f.write(f"- **Status:** {host.get('status', 'unknown')}\n")
                    f.write(f"- **Open Ports:** {', '.join(map(str, host['ports'])) if host['ports'] else 'None'}\n")
                    f.write(f"- **Last Seen:** {host.get('last_seen', 'N/A')}\n\n")
            
            self.log(f"Report exported to {report_path}")
            messagebox.showinfo("Export Complete", f"Report exported to {report_path}")
        except Exception as e:
            self.log(f"Export error: {e}")
            messagebox.showerror("Export Error", f"Failed to export report: {e}")
    
    def clear_database(self):
        """Clear the database"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear the database?"):
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
                messagebox.showerror("Error", f"Failed to clear database: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkReconGUI(root)
    root.mainloop()

