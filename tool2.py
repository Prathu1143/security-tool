import subprocess
import platform
import requests
import re
import ipaddress
import pyfiglet

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

# Function to ping an IP address or domain
def run_ping(target, packet_count=4):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    try:
        result = subprocess.run(["ping", param, str(packet_count), target], 
                                capture_output=True, text=True, shell=True)
        print(f"Ping output for {target}:")
        print(result.stdout)
        if result.stderr:
            print(f"Error: {result.stderr}")
        if result.returncode != 0:
            print(f"Ping failed with return code {result.returncode}")
        else:
            print("Ping was successful!")
    except Exception as e:
        print(f"Error occurred while pinging {target}: {e}")

# Function to get geolocation of an IP address
def get_geolocation(ip):
    try:
        api_key = "YOUR_API_KEY"  # Replace with your actual API key
        response = requests.get(f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}")
        print(f"API Response: {response.status_code}, {response.text}")
        location_data = response.json()

        # Safely extract city and country information
        city = location_data.get('city', 'N/A')
        country = location_data.get('country_name', 'N/A')
        print(f"IP: {ip}, Location: {city}, {country}")
    except Exception as e:
        print(f"Error fetching geolocation for IP {ip}: {e}")

# Main menu function
def main_menu():
    # Generate and print the banner
    text = pyfiglet.figlet_format("Project P ")
    print(text)

    while True:
        print("Main Menu:")
        print("1. Ping an IP address")
        print("2. Get geolocation of an IP address")
        print("3. Ping a website")
        print("4. Exit")

        choice = input("Select an option (1-4): ").strip()

        if choice == '1':
            # Option 1: Ping an IP address
            print("Enter an IP address:")
            ip = input().strip()

            if is_valid_ip(ip):
                run_ping(ip)
            else:
                print("Invalid IP address.")
        
        elif choice == '2':
            # Option 2: Get geolocation of an IP address
            print("Enter an IP address to fetch geolocation:")
            ip = input().strip()

            if is_valid_ip(ip):
                get_geolocation(ip)
            else:
                print("Invalid IP address.")
        
        elif choice == '3':
            # Option 3: Ping a website
            print("Enter a website domain:")
            website = input().strip()

            if is_valid_domain(website):
                run_ping(website)
            else:
                print("Invalid website domain.")
        
        elif choice == '4':
            # Option 4: Exit
            print("Exiting program.")
            break
        
        else:
            print("Invalid option. Please select a valid option from the menu.")

        # Ask to run again or go back to the main menu
        cont = input("Do you want to go back to the main menu? (y/n): ").strip().lower()
        if cont != 'y':  # Only continue if the user enters 'y'
            print("Goodbye!")
            break

# Run the main menu
if __name__ == "__main__":
    main_menu()
