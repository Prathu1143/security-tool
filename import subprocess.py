import subprocess
import pyfiglet
import ipaddress
import re
import platform

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

# Generate and print the banner
text = pyfiglet.figlet_format("Website Ping")
print(text)

# Prompt for user input
print("Enter an IP address or website name:")
i = input().strip()

# Check if the input is a valid IP address or domain name
if is_valid_ip(i) or is_valid_domain(i):
    print(f"Pinging {i}...")

    # Adjust ping command based on the platform (Windows vs. Linux/Mac)
    param = '-n' if platform.system().lower() == 'windows' else '-c'

    # Run the ping command and capture output
    try:
        result = subprocess.run(["ping", param, "4", i], capture_output=True, text=True)
        print(result.stdout)  # Print the ping output
    except subprocess.CalledProcessError as e:
        print(f"Ping failed: {e}")

    # Wait for user input before closing (to keep the window open)
    input("Press Enter to exit...")

else:
    print("Invalid IP address or domain name.")
    input("Press Enter to exit...")
