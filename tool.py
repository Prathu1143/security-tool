import subprocess
import pyfiglet
import ipaddress
import re
import platform
import threading
import schedule
import time
import smtplib
import requests
import matplotlib.pyplot as plt

# Function to validate IP address
def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

# Function to validate domain name
def is_valid_domain(domain):
    domain_regex = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$'
    return re.match(domain_regex, domain) is not None

# Function to send email alert
def send_email_alert(subject, message):
    server = smtplib.SMTP("smtp.example.com", 587)
    server.starttls()
    server.login("your_email@example.com", "password")
    email_message = f"Subject: {subject}\n\n{message}"
    server.sendmail("from@example.com", "to@example.com", email_message)
    server.quit()

# Function to run ping and parse results
def ping_address(address):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        result = subprocess.run(["ping", param, "4", address], capture_output=True, text=True)
        print(result.stdout)
        parse_ping_result(result.stdout)
        log_ping_result(address, result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Ping failed: {e}")
        send_email_alert("Ping Failure", f"Failed to ping {address}")

# Function to parse ping result and extract latency info
def parse_ping_result(ping_output):
    packet_loss = re.search(r'(\d+)% packet loss', ping_output)
    rtt = re.search(r'(\d+.\d+)/(\d+.\d+)/(\d+.\d+)', ping_output)  # min/avg/max
    if packet_loss:
        print(f"Packet loss: {packet_loss.group(1)}%")
    if rtt:
        print(f"Latency (min/avg/max): {rtt.group(1)}/{rtt.group(2)}/{rtt.group(3)} ms")

# Function to log ping result to a file
def log_ping_result(address, result):
    with open("ping_log.txt", "a") as log_file:
        log_file.write(f"Ping to {address}:\n")
        log_file.write(result)
        log_file.write("\n---\n")

# Function to plot latency over time
def plot_latency(latencies):
    plt.plot(latencies)
    plt.ylabel('Latency (ms)')
    plt.xlabel('Ping Attempts')
    plt.show()

# Function to get geolocation of IP
def get_geolocation(ip):
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    location_data = response.json()
    print(f"IP: {ip}, Location: {location_data['city']}, {location_data['country']}")

# Function to ping multiple addresses concurrently
def ping_multiple(addresses):
    threads = []
    for addr in addresses:
        thread = threading.Thread(target=ping_address, args=(addr,))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

# Function to schedule pings
def scheduled_ping():
    address = "8.8.8.8"
    ping_address(address)

# Main Function
def main():
    text = pyfiglet.figlet_format("Advanced Ping Tool")
    print(text)

    # Get input from the user
    print("Enter an IP address or website name:")
    i = input().strip()

    # Validate input
    if is_valid_ip(i) or is_valid_domain(i):
        get_geolocation(i)
        print(f"Pinging {i}...")
        ping_address(i)
    else:
        print("Invalid IP address or domain name.")
    
    # Schedule pings at intervals
    schedule.every(5).minutes.do(scheduled_ping)

    # Keep the schedule running
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()
