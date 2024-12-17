import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk
import subprocess
import ipaddress
import re
import platform
import requests
import socket

# Function to validate if the input is an IP address
def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

# Function to validate if the input is a valid domain name
def is_valid_domain(domain):
    domain_regex = r'^(?:[a-zA-Z0-9]' \
                   r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)' \
                   r'+[a-zA-Z]{2,6}$'
    return re.match(domain_regex, domain) is not None

# Function to run ping command
def run_ping():
    target = entry_target.get()
    if not (is_valid_ip(target) or is_valid_domain(target)):
        messagebox.showerror("Error", "Invalid IP address or domain name.")
        return

    param = '-n' if platform.system().lower() == 'windows' else '-c'
    result = subprocess.run(["ping", param, "4", target], capture_output=True, text=True)
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, result.stdout)  # Insert ping output
    parse_ping_result(result.stdout)

# Function to parse ping results for statistics
def parse_ping_result(ping_output):
    packet_loss = re.search(r'(\d+)% packet loss', ping_output)
    rtt = re.search(r'(\d+.\d+)/(\d+.\d+)/(\d+.\d+)', ping_output)
    if packet_loss:
        output_text.insert(tk.END, f"Packet loss: {packet_loss.group(1)}%\n")
    if rtt:
        output_text.insert(tk.END, f"Latency (min/avg/max): {rtt.group(1)}/{rtt.group(2)}/{rtt.group(3)} ms\n")

# Function to fetch geolocation of an IP
def get_geolocation():
    ip = entry_target.get()
    if not is_valid_ip(ip):
        messagebox.showerror("Error", "Invalid IP address.")
        return

    api_key = "YOUR_API_KEY"  # Replace with your actual API key
    try:
        response = requests.get(f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}")
        response.raise_for_status()  # Raise an error for bad responses
        location_data = response.json()
        
        city = location_data.get('city', 'N/A')
        country = location_data.get('country_name', 'N/A')

        output_text.insert(tk.END, f"IP: {ip}, Location: {city}, {country}\n")
    except Exception as e:
        messagebox.showerror("Error", f"Error fetching geolocation: {e}")

# Function to run traceroute
def run_traceroute():
    target = entry_target.get()
    if not (is_valid_ip(target) or is_valid_domain(target)):
        messagebox.showerror("Error", "Invalid IP address or domain name.")
        return

    cmd = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'
    result = subprocess.run([cmd, target], capture_output=True, text=True)
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, result.stdout)  # Insert traceroute output

# Function to scan ports (common ports)
def scan_ports():
    target = entry_target.get()
    if not is_valid_ip(target):
        messagebox.showerror("Error", "Invalid IP address for port scanning.")
        return

    output_text.delete(1.0, tk.END)  # Clear previous output
    open_ports = []
    common_ports = [22, 23, 80, 443, 8080]  # You can add more common ports to scan

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 second timeout for each port
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    if open_ports:
        output_text.insert(tk.END, f"Open Ports on {target}: {', '.join(map(str, open_ports))}\n")
    else:
        output_text.insert(tk.END, f"No open ports found on {target}.\n")

# Create the main application window
root = tk.Tk()
root.title("Project P ")
root.geometry("600x600")  # Set window size

# Add a style for the theme
style = ttk.Style()
style.theme_use("clam")  # Use clam theme for modern look

# Set background color for the window
root.configure(bg="#1a1a2e")

# Create a title label with custom font and color
label_title = tk.Label(root, text="Project P ", font=("Helvetica", 24, "bold"), bg="#1a1a2e", fg="white")
label_title.pack(pady=10)

# Create a label and entry for the target IP/domain
label_target = tk.Label(root, text="Enter IP Address or Domain:", font=("Helvetica", 12), bg="#1a1a2e", fg="white")
label_target.pack(pady=5)

entry_target = tk.Entry(root, width=40, font=("Helvetica", 14))
entry_target.pack(pady=5)

# Create buttons for actions with custom styling
button_ping = tk.Button(root, text="Ping", font=("Helvetica", 12), bg="#0f4c75", fg="white", command=run_ping)
button_ping.pack(pady=10, ipadx=10)

button_geo = tk.Button(root, text="Get Geolocation", font=("Helvetica", 12), bg="#3282b8", fg="white", command=get_geolocation)
button_geo.pack(pady=10, ipadx=10)

button_traceroute = tk.Button(root, text="Traceroute", font=("Helvetica", 12), bg="#bbe1fa", fg="#1b262c", command=run_traceroute)
button_traceroute.pack(pady=10, ipadx=10)

button_scan_ports = tk.Button(root, text="Scan Ports", font=("Helvetica", 12), bg="#0f4c75", fg="white", command=scan_ports)
button_scan_ports.pack(pady=10, ipadx=10)

# Create a scrolled text area to display output with modern styling
output_text = scrolledtext.ScrolledText(root, width=65, height=15, font=("Courier", 12), bg="#0d1b2a", fg="white", insertbackground="white")
output_text.pack(pady=10)

# Run the GUI event loop
root.mainloop()
