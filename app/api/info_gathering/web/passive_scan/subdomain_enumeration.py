import os
import subprocess
from app.api.requests.request_flow import target_domain  
from urllib.parse import urlparse
import threading
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["sub_enum"]  # Database name
collection = db["live_subdomains"]  # Collection name

# List to store subdomains
subdomains_list = []

# Function to run Findomain
def run_findomain(target_domain):
    print(f"start subdomain_enumeration for {target_domain}...stage 1")
    try:
        result = subprocess.run(['findomain', '-t', target_domain], capture_output=True, text=True, check=True)
        subdomains_list.extend(result.stdout.splitlines())  # Add Findomain results to the list
    except subprocess.CalledProcessError:
        print("Error running subdomain_enumeration stage 1")

# Function to run Subfinder
def run_subfinder(target_domain):
    print(f"start subdomain_enumeration for {target_domain}...stage 2")
    try:
        result = subprocess.run(['subfinder', '-d', target_domain], capture_output=True, text=True, check=True)
        subdomains_list.extend(result.stdout.splitlines())  # Add Subfinder results to the list
    except subprocess.CalledProcessError:
        print("Error running subdomain_enumeration stage 2")

# Function to run Assetfinder
def run_assetfinder(target_domain):
    print(f"start subdomain_enumeration for {target_domain}...stage 3")
    try:
        result = subprocess.run(['assetfinder', '--subs-only', target_domain], capture_output=True, text=True, check=True)
        subdomains_list.extend(result.stdout.splitlines())  # Add Assetfinder results to the list
    except subprocess.CalledProcessError:
        print("Error running subdomain_enumeration stage 3")

# Function to store live subdomains in MongoDB
def store_in_mongodb(live_subdomains):
    if not live_subdomains:
        print("No live subdomains to store.")
        return
    
    # Prepare documents for MongoDB
    subdomain_docs = [{"subdomain": sub, "source": "sub_enum"} for sub in live_subdomains]

    # Insert into MongoDB
    collection.insert_many(subdomain_docs)
    print(f"Stored {len(live_subdomains)} live subdomains in MongoDB.")

# Function to check live subdomains using httpx-toolkit
def check_live_subdomains():
    print("Checking live subdomains using httpx-toolkit...")
    try:
        with open("temp_subdomains.txt", "w") as f:
            for subdomain in subdomains_list:
                f.write(f"{subdomain}\n")

        result = subprocess.run(['httpx-toolkit', '-l', 'temp_subdomains.txt', '-mc', '200'], capture_output=True, text=True, check=True)
        live_subdomains_raw = result.stdout.splitlines()

        live_subdomains = []
        for subdomain in live_subdomains_raw:
            parsed_url = urlparse(subdomain)
            if parsed_url.hostname:
                live_subdomains.append(parsed_url.hostname)

        subprocess.run(['rm', 'temp_subdomains.txt'])

        # Store results in MongoDB
        store_in_mongodb(live_subdomains)

        return live_subdomains

    except subprocess.CalledProcessError as e:
        print(f"Error running httpx-toolkit: {e}")
        return []

# Main function to run all tools in parallel
def run_subdomain_enum(target_domain):
    threads = []

    # Start threads for each tool
    threads.append(threading.Thread(target=run_findomain, args=(target_domain,)))
    threads.append(threading.Thread(target=run_subfinder, args=(target_domain,)))
    threads.append(threading.Thread(target=run_assetfinder, args=(target_domain,)))

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    # Remove duplicates by converting to a set
    unique_subdomains = set(subdomains_list)
    
    # Check for live subdomains
    live_subdomains = check_live_subdomains()
    
    # Print live subdomains
    print("Live subdomains found:", live_subdomains)

# Run only when executed directly
if __name__ == "__main__":
    run_subdomain_enum(target_domain)
