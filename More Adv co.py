import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk
import subprocess
import ipaddress
import re
import platform
import requests
import socket
import whois
import dns.resolver
import shodan

# Add your Shodan API Key here
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"

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

# Function for IP address resolution
def resolve_ip():
    domain = entry_target.get()
    if not is_valid_domain(domain):
        messagebox.showerror("Error", "Invalid domain name.")
        return

    try:
        ip_address = socket.gethostbyname(domain)
        output_text.insert(tk.END, f"Domain: {domain}, IP Address: {ip_address}\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error resolving IP: {e}\n")

# Function for WHOIS lookup
def whois_lookup():
    domain = entry_target.get()
    if not is_valid_domain(domain):
        messagebox.showerror("Error", "Invalid domain name.")
        return

    try:
        whois_info = whois.whois(domain)
        output_text.insert(tk.END, str(whois_info) + "\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error performing WHOIS lookup: {e}\n")

# Function to retrieve DNS records
def get_dns_records():
    domain = entry_target.get()
    if not is_valid_domain(domain):
        messagebox.showerror("Error", "Invalid domain name.")
        return

    try:
        resolver = dns.resolver.Resolver()
        dns_records = resolver.resolve(domain, 'A')  # Retrieving A records
        for ipval in dns_records:
            output_text.insert(tk.END, f"DNS Record: {ipval.to_text()}\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error retrieving DNS records: {e}\n")

# Function to perform Shodan lookup
def shodan_lookup():
    ip = entry_target.get()
    if not is_valid_ip(ip):
        messagebox.showerror("Error", "Invalid IP address.")
        return

    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
        output_text.insert(tk.END, f"Shodan Results for {ip}:\n")
        output_text.insert(tk.END, f"Organization: {host.get('org', 'n/a')}\n")
        output_text.insert(tk.END, f"Operating System: {host.get('os', 'n/a')}\n")

        for item in host['data']:
            output_text.insert(tk.END, f"Port: {item['port']}, Banner: {item['data']}\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error performing Shodan lookup: {e}\n")

# Function to retrieve HTTP headers
def get_http_headers():
    url = entry_target.get()
    if not url.startswith('http'):
        url = 'http://' + url  # Add http scheme if missing

    try:
        response = requests.head(url)
        output_text.insert(tk.END, f"HTTP Headers for {url}:\n")
        for header, value in response.headers.items():
            output_text.insert(tk.END, f"{header}: {value}\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error retrieving HTTP headers: {e}\n")

# Function to clear the output area
def clear_output():
    output_text.delete(1.0, tk.END)

# Create the main application window
root = tk.Tk()
root.title("Project P ")
root.geometry("800x600")  # Set window size

# Add a style for the theme
style = ttk.Style()
style.theme_use("clam")  # Use clam theme for modern look

# Set background color for the window
root.configure(bg="#1a1a2e")

# Create a title label with custom font and color
label_title = tk.Label(root, text="Project P ", font=("Helvetica", 24, "bold"), bg="#1a1a2e", fg="white")
label_title.grid(row=0, column=0, columnspan=5, pady=10)

# Create a label and entry for the target IP/domain
label_target = tk.Label(root, text="Enter IP Address or Domain:", font=("Helvetica", 12), bg="#1a1a2e", fg="white")
label_target.grid(row=1, column=0, columnspan=5, pady=5)

entry_target = tk.Entry(root, width=40, font=("Helvetica", 14))
entry_target.grid(row=2, column=0, columnspan=5, pady=5)

# Create buttons for actions with custom styling
button_ping = tk.Button(root, text="Ping", font=("Helvetica", 12), bg="#0f4c75", fg="white", command=run_ping)
button_ping.grid(row=3, column=0, padx=10, pady=10)

button_geo = tk.Button(root, text="Get Geolocation", font=("Helvetica", 12), bg="#3282b8", fg="white", command=get_geolocation)
button_geo.grid(row=3, column=1, padx=10, pady=10)

button_traceroute = tk.Button(root, text="Traceroute", font=("Helvetica", 12), bg="#bbe1fa", fg="#1b262c", command=run_traceroute)
button_traceroute.grid(row=3, column=2, padx=10, pady=10)

button_scan_ports = tk.Button(root, text="Scan Ports", font=("Helvetica", 12), bg="#0f4c75", fg="white", command=scan_ports)
button_scan_ports.grid(row=3, column=3, padx=10, pady=10)

# New feature buttons
button_resolve_ip = tk.Button(root, text="Resolve IP", font=("Helvetica", 12), bg="#0f4c75", fg="white", command=resolve_ip)
button_resolve_ip.grid(row=4, column=0, padx=10, pady=10)

button_whois = tk.Button(root, text="WHOIS Lookup", font=("Helvetica", 12), bg="#3282b8", fg="white", command=whois_lookup)
button_whois.grid(row=4, column=1, padx=10, pady=10)

button_dns = tk.Button(root, text="Get DNS Records", font=("Helvetica", 12), bg="#bbe1fa", fg="#1b262c", command=get_dns_records)
button_dns.grid(row=4, column=2, padx=10, pady=10)

button_shodan = tk.Button(root, text="Shodan Lookup", font=("Helvetica", 12), bg="#0f4c75", fg="white", command=shodan_lookup)
button_shodan.grid(row=4, column=3, padx=10, pady=10)

button_http_headers = tk.Button(root, text="Get HTTP Headers", font=("Helvetica", 12), bg="#3282b8", fg="white", command=get_http_headers)
button_http_headers.grid(row=4, column=4, padx=10, pady=10)

# Clear button
button_clear = tk.Button(root, text="Clear Output", font=("Helvetica", 12), bg="#ff4d4d", fg="white", command=clear_output)
button_clear.grid(row=5, column=2, padx=10, pady=10)

# Create a scrolled text area to display output with modern styling
output_text = scrolledtext.ScrolledText(root, width=75, height=15, font=("Courier", 12), bg="#0d1b2a", fg="white", insertbackground="white")
output_text.grid(row=6, column=0, columnspan=5, padx=10, pady=10)

# Run the GUI event loop
root.mainloop()
