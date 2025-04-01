import subprocess
import re
import asyncio
from app.api.requests.request_flow import target_url  
from utils import get_domain_from_url
from app.config.log_middleware import LoggingMiddleware
from app.api.models.information import WebInfoGatheringModel

target_domain = get_domain_from_url(target_url)

logger = LoggingMiddleware()

@logger
async def get_archived_urls(subdomain):
    """Retrieve archived URLs using waybackurls."""
    try:
        result = subprocess.run(
            ["waybackurls"], input=subdomain, capture_output=True, text=True, check=True
        )
        return result.stdout.splitlines()  # Split output into individual URLs
    except subprocess.CalledProcessError:
        logger.error(f"Error retrieving archived URLs for {subdomain}")
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

async def retrieve_archived_urls(subdomains):
    """Process each subdomain to find and return potential injection URLs."""
    archive_urls = {}  # Renamed result to archive_urls

    for subdomain in subdomains:
        logger.info(f"Retrieving archived URLs for {subdomain}...")
        urls = await get_archived_urls(subdomain)
        filtered_urls = filter_injection_urls(urls)

        if filtered_urls:
            for url in filtered_urls:
                logger.info(f"Potential injection URL: {url}")
            archive_urls[subdomain] = filtered_urls  # Store filtered URLs in archive_urls
        else:
            logger.info(f"No URLs with potential injection points found for {subdomain}.")

    logger.info("Process completed!")
    return archive_urls

async def run_archives_for_target_domain(domain: str):
    """Run the archived URL retrieval service for all subdomains of the target domain."""
    
    # Step 1: Retrieve subdomains from the database (or by running subdomain enumeration)
    info_gathering = await WebInfoGatheringModel.find_one({"target": domain})
    
    if not info_gathering:
        logger.error(f"No information gathering document found for {domain}. Please run subdomain enumeration first.")
        return
    
    subdomains = [subdomain["subdomain"] for subdomain in info_gathering.subdomains]
    
    # Step 2: Retrieve archived URLs for the subdomains
    archive_urls = await retrieve_archived_urls(subdomains)
    
    # Step 3: Update the information gathering document with archived URLs
    info_gathering.archives_urls = archive_urls
    
    # Save the updated document in the database
    await info_gathering.save()
    logger.info(f"Updated archived URLs for {domain} saved to MongoDB.")
