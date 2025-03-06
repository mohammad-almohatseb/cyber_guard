import os
import subprocess
from app.api.requests.request_flow import target_domain  
from urllib.parse import urlparse
import threading


# Function to run Amass
def run_amass(target_domain, result_list):
    print(f"start subdomain_enumeration for {target_domain}...stage 1")
    try:
        result = subprocess.run(['amass', 'enum', '-d', target_domain], capture_output=True, text=True, check=True)
        result_list.extend(result.stdout.splitlines())  # Add Amass results to the list
    except subprocess.CalledProcessError:
        print("Error running subdomain_enumeration stage 1")

# Function to run Subfinder
def run_subfinder(target_domain, result_list):
    print(f"start subdomain_enumeration for {target_domain}...stage 2")
    try:
        result = subprocess.run(['subfinder', '-d', target_domain], capture_output=True, text=True, check=True)
        result_list.extend(result.stdout.splitlines())  # Add Subfinder results to the list
    except subprocess.CalledProcessError:
        print("Error running subdomain_enumeration stage 2")

# Function to check live subdomains using httpx-toolkit
def check_live_subdomains(result_list, live_subdomains):
    print("Checking live subdomains using httpx-toolkit...")
    try:
        # Save the subdomains in a temporary file for httpx-toolkit input
        with open("temp_subdomains.txt", "w") as f:
            for subdomain in result_list:
                f.write(f"{subdomain}\n")

        # Run httpx-toolkit to filter live subdomains and capture the result
        result = subprocess.run(['httpx-toolkit', '-l', 'temp_subdomains.txt', '-mc', '200'], capture_output=True, text=True, check=True)

        # Parse the live subdomains from the output
        live_subdomains_raw = result.stdout.splitlines()

        # Remove protocol (http:// or https://) and store only the subdomain
        for subdomain in live_subdomains_raw:
            parsed_url = urlparse(subdomain)
            live_subdomains.append(parsed_url.hostname)  # Add only the hostname (subdomain)

        # Clean up the temporary file
        subprocess.run(['rm', 'temp_subdomains.txt'])

    except subprocess.CalledProcessError as e:
        print(f"Error running httpx-toolkit: {e}")

# Main function to run both tools in parallel and filter duplicates
def run_subdomain_enum(target_domain):
    # Create a shared list to store results
    result_list = []

    # Create a list to store live subdomains
    live_subdomains = []

    # Create threads for running Amass and Subfinder concurrently
    amass_thread = threading.Thread(target=run_amass, args=(target_domain, result_list))
    subfinder_thread = threading.Thread(target=run_subfinder, args=(target_domain, result_list))

    # Start both threads
    amass_thread.start()
    subfinder_thread.start()

    # Wait for both threads to finish
    amass_thread.join()
    subfinder_thread.join()

    # Filter duplicates using a set
    unique_subdomains = set(result_list)

    # Check live subdomains
    check_live_subdomains(unique_subdomains, live_subdomains)

    # Store final live subdomains in a variable
    final_live_subdomain = live_subdomains

    # Print live subdomains
    print(f"Live subdomains for {target_domain}:")
    for subdomain in final_live_subdomain:
        print(subdomain)

# Start the enumeration process
if __name__ == "__main__":
    run_subdomain_enum(target_domain)

