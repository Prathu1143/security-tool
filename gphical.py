import tkinter as tk
from tkinter import messagebox, scrolledtext
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
root.title("Project P")

# Create a label and entry for the target IP/domain
label_target = tk.Label(root, text="Enter IP Address or Domain:")
label_target.pack()

entry_target = tk.Entry(root, width=50)
entry_target.pack()

# Create buttons for actions
button_ping = tk.Button(root, text="Ping", command=run_ping)
button_ping.pack(pady=5)

button_geo = tk.Button(root, text="Get Geolocation", command=get_geolocation)
button_geo.pack(pady=5)

button_traceroute = tk.Button(root, text="Traceroute", command=run_traceroute)
button_traceroute.pack(pady=5)

button_scan_ports = tk.Button(root, text="Scan Ports", command=scan_ports)
button_scan_ports.pack(pady=5)

# Create a scrolled text area to display output
output_text = scrolledtext.ScrolledText(root, width=60, height=20)
output_text.pack(pady=10)

# Start the GUI event loop
root.mainloop()
