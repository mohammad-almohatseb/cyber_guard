import subprocess
from app.api.requests.request_flow import target_url
from urllib.parse import urlparse
import threading
import httpx  
import asyncio


# Function to parse domain from URL

def get_domain_from_url(url_to_process):  # Updated argument name
    parsed_url = urlparse(url_to_process)
    if not parsed_url.netloc:
        raise ValueError("Invalid URL provided")
    return parsed_url.netloc

domain = get_domain_from_url(target_url)
print(f"Extracted domain: {domain}")




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

# Function to check live subdomains using httpx
async def check_live_subdomains(subdomains):
    print("Checking live subdomains using httpx...")
    live_subdomains = []
    async with httpx.AsyncClient() as client:
        tasks = [client.get(f"http://{subdomain}", timeout=5) for subdomain in subdomains]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for subdomain, response in zip(subdomains, responses):
            if isinstance(response, httpx.Response) and response.status_code == 200:
                live_subdomains.append(subdomain)
    return live_subdomains

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

    # Check for live subdomains (async call)
    live_subdomains = asyncio.run(check_live_subdomains(unique_subdomains))

    print("Live subdomains found:", live_subdomains)

if __name__ == "__main__":
    
    parsed_domain = get_domain_from_url(target_url)
    run_subdomain_enum(parsed_domain)
    
    print("Unique subdomains found:", subdomains_list)
    
    print("Total number of subdomains found:", len(subdomains_list))
