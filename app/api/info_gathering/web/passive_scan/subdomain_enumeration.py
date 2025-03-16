import subprocess
import threading
import httpx
import asyncio
from app.api.requests.request_flow import target_url
from utils import get_domain_from_url

try:
    domain = get_domain_from_url(target_url)
    print(f"Extracted domain: {domain}")
except ValueError as e:
    print(f"Error: {e}")
    exit(1)

subdomains_list = []

def run_findomain(target_domain):
    print(f"Start subdomain enumeration for {target_domain}... Stage 1")
    try:
        result = subprocess.run(['findomain', '-t', target_domain], capture_output=True, text=True, check=True)
        subdomains_list.extend(result.stdout.splitlines())
    except subprocess.CalledProcessError:
        print("Error running subdomain enumeration stage 1")

def run_subfinder(target_domain):
    print(f"Start subdomain enumeration for {target_domain}... Stage 2")
    try:
        result = subprocess.run(['subfinder', '-d', target_domain], capture_output=True, text=True, check=True)
        subdomains_list.extend(result.stdout.splitlines())
    except subprocess.CalledProcessError:
        print("Error running subdomain enumeration stage 2")

def run_assetfinder(target_domain):
    print(f"Start subdomain enumeration for {target_domain}... Stage 3")
    try:
        result = subprocess.run(['assetfinder', '--subs-only', target_domain], capture_output=True, text=True, check=True)
        subdomains_list.extend(result.stdout.splitlines())
    except subprocess.CalledProcessError:
        print("Error running subdomain enumeration stage 3")

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

def run_subdomain_enum(target_domain):
    threads = [
        threading.Thread(target=run_findomain, args=(target_domain,)),
        threading.Thread(target=run_subfinder, args=(target_domain,)),
        threading.Thread(target=run_assetfinder, args=(target_domain,))
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    unique_subdomains = set(subdomains_list)

    live_subdomains = asyncio.run(check_live_subdomains(unique_subdomains))

    print("Live subdomains found:", live_subdomains)

if __name__ == "__main__":
    run_subdomain_enum(domain)
