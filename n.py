import subprocess
import pyfiglet
import ipaddress
import re
import platform
import threading
import time
import requests
import matplotlib.pyplot as plt
import dns.resolver
import shodan
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

# Function to parse ping results for statistics
def parse_ping_result(ping_output):
    packet_loss = re.search(r'(\d+)% packet loss', ping_output)
    rtt = re.search(r'(\d+.\d+)/(\d+.\d+)/(\d+.\d+)', ping_output)  # min/avg/max/mdev
    if packet_loss:
        print(f"Packet loss: {packet_loss.group(1)}%")
    if rtt:
        print(f"Latency (min/avg/max): {rtt.group(1)}/{rtt.group(2)}/{rtt.group(3)} ms")

# Function to run ping command and capture output
def run_ping(target, packet_count=4):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    result = subprocess.run(["ping", param, str(packet_count), target], capture_output=True, text=True)
    print(result.stdout)
    parse_ping_result(result.stdout)
    log_ping_result(target, result.stdout)

# Function to log ping results to a file
def log_ping_result(target, result):
    with open("ping_log.txt", "a") as log_file:
        log_file.write(f"Ping to {target} at {time.ctime()}:\n")
        log_file.write(result)
        log_file.write("\n---\n")

# Function to fetch geolocation of an IP
def get_geolocation(ip):
    try:
        api_key = "YOUR_API_KEY"  # Replace with your API key
        response = requests.get(f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}")
        location_data = response.json()
        
        # Check if 'city' and 'country' are in the response
        city = location_data.get('city', 'N/A')  # Default to 'N/A' if not found
        country = location_data.get('country_name', 'N/A')  # Default to 'N/A' if not found
        
        print(f"IP: {ip}, Location: {city}, {country}")
    except Exception as e:
        print(f"Error fetching geolocation for IP {ip}: {e}")

# Function to resolve a domain to an IP address
def resolve_ip(domain):
    try:
        result = socket.gethostbyname(domain)
        print(f"The IP address of {domain} is {result}")
    except socket.gaierror:
        print(f"Could not resolve {domain}")

# Function to get DNS records
def get_dns_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            print(f"DNS Record for {domain}: {rdata}")
    except Exception as e:
        print(f"Error retrieving DNS records for {domain}: {e}")

# Function to perform Shodan lookup
def shodan_lookup(ip):
    try:
        api_key = "YOUR_SHODAN_API_KEY"  # Replace with your Shodan API key
        api = shodan.Shodan(api_key)
        data = api.host(ip)
        
        print(f"Shodan data for IP {ip}:")
        print(f"IP: {data['ip_str']}")
        print(f"Organization: {data.get('org', 'N/A')}")
        print(f"Operating System: {data.get('os', 'N/A')}")
        print(f"Ports: {data['ports']}")
    except Exception as e:
        print(f"Error fetching Shodan data for IP {ip}: {e}")

# Function to get HTTP headers from a URL
def get_http_headers(url):
    try:
        response = requests.head(url)
        print(f"HTTP Headers for {url}:")
        for header, value in response.headers.items():
            print(f"{header}: {value}")
    except Exception as e:
        print(f"Error fetching HTTP headers for {url}: {e}")

# Function to plot latency results
def plot_latency(latencies):
    plt.plot(latencies)
    plt.ylabel('Latency (ms)')
    plt.xlabel('Ping Attempts')
    plt.show()

# Function to run traceroute command
def run_traceroute(target):
    cmd = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'
    result = subprocess.run([cmd, target], capture_output=True, text=True)
    print(result.stdout)

# Function to ping multiple addresses concurrently
def ping_multiple(addresses):
    threads = []
    for addr in addresses:
        thread = threading.Thread(target=run_ping, args=(addr.strip(),))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

# Main program
if __name__ == "__main__":
    # Generate and print the banner
    text = pyfiglet.figlet_format("Project P ")
    print(text)

    while True:
        # Main menu with options
        print(f"\nChoose an option:\n1. Enter an IP address\n2. Enter a website/domain name\n3. Exit")
        main_option = input("Enter option number: ").strip()

        if main_option == "1":
            # Prompt for IP address
            i = input("Enter the IP address: ").strip()

            if not is_valid_ip(i):
                print("Invalid IP address. Returning to main menu.")
                continue

        elif main_option == "2":
            # Prompt for website/domain name
            i = input("Enter the website/domain name: ").strip()

            if not is_valid_domain(i):
                print("Invalid domain name. Returning to main menu.")
                continue

        elif main_option == "3":
            print("Exiting the program.")
            break

        else:
            print("Invalid option. Please choose again.")
            continue

        # Once IP or domain is validated, choose an action
        while True:
            print(f"\nChoose an action for {i}:\n1. Ping\n2. Traceroute\n3. Ping multiple addresses\n4. Get Geolocation\n5. Resolve IP\n6. Get DNS Records\n7. Shodan Lookup\n8. Get HTTPS Headers\n9. Exit to Main Menu")
            option = input("Enter action number: ").strip()

            if option == "1":
                # Basic ping with statistics
                run_ping(i)

            elif option == "2":
                # Run traceroute
                run_traceroute(i)

            elif option == "3":
                # Ping multiple addresses concurrently
                addresses = input("Enter multiple addresses (comma-separated): ").strip().split(',')
                ping_multiple(addresses)

            elif option == "4":
                # Fetch geolocation
                get_geolocation(i)

            elif option == "5":
                # Resolve IP address
                resolve_ip(i)

            elif option == "6":
                # Get DNS records
                get_dns_records(i)

            elif option == "7":
                # Shodan lookup
                shodan_lookup(i)

            elif option == "8":
                # Get HTTPS headers
                url = input("Enter the URL (e.g., http://example.com): ").strip()
                get_http_headers(url)

            elif option == "9":
                print("Returning to Main Menu...\n")
                break  # Exit the inner loop to return to the main menu

            else:
                print("Invalid option. Please try again.")
