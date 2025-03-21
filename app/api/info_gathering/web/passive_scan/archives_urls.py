import subprocess
import re
import asyncio
from app.api.requests.request_flow import target_url  
from utils import get_domain_from_url
from models.information import InfoGatheringModel, ArchivedURL

target_domain = get_domain_from_url(target_url)

RED = "\033[31m"
RESET = "\033[0m"  # Reset to default color

async def get_archived_urls(subdomain):
    """Retrieve archived URLs using waybackurls."""
    try:
        result = subprocess.run(
            ["waybackurls"], input=subdomain, capture_output=True, text=True, check=True
        )
        return result.stdout.splitlines()  # Split output into individual URLs
    except subprocess.CalledProcessError:
        print(f"Error retrieving archived URLs for {subdomain}")
        return []

def filter_injection_urls(urls):
    """Filter URLs that contain query parameters (potential injection points)."""
    injection_patterns = [
        r"[?&][^=]+=[^&]+",  # Matches query parameters (e.g., ?param=value or &param=value)
        r"(?<=\?)\w+=\w+",  # Matches simple query parameters (e.g., ?id=1)
        r"(?<=\?)\w+",  # Matches parameters without values (e.g., ?id)
        r"(?<=&)\w+=\w+",  # Matches additional parameters after & (e.g., &id=1)
    ]
    
    return [url for url in urls if any(re.search(pattern, url) for pattern in injection_patterns)]

async def store_archived_urls(target_domain, archived_urls):
    """Stores filtered archived URLs in the InfoGatheringModel collection."""
    info_gathering = await InfoGatheringModel.find_one({"target": target_domain, "target_type": "web"})

    if not info_gathering:
        info_gathering = InfoGatheringModel(
            target=target_domain,
            target_type="web",  # Ensures it's categorized as a web scan
        )

    # Store the archived URLs with potential injection points
    info_gathering.archived_urls = [ArchivedURL(url=url) for url in archived_urls]

    await info_gathering.save()
    print(f"Stored {len(archived_urls)} archived URLs in the database for: {target_domain}")

async def retrieve_archived_urls(subdomains):
    """Process each subdomain to find and store potential injection URLs."""
    print("Starting the process...")
    results = {}

    for subdomain in subdomains:
        print(f"{RED}Archived URLs for {subdomain} with potential injection points:{RESET}")
        urls = await get_archived_urls(subdomain)
        filtered_urls = filter_injection_urls(urls)

        if filtered_urls:
            for url in filtered_urls:
                print(url)
            results[subdomain] = filtered_urls

            # Store in the database
            await store_archived_urls(subdomain, filtered_urls)
        else:
            print("No URLs with potential injection points found.")

    print("Process completed!")
    return results  

if __name__ == "__main__":
    asyncio.run(retrieve_archived_urls([target_domain]))
