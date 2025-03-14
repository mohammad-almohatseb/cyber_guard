import subprocess
from pymongo import MongoClient
import re
from app.api.requests.request_flow import target_domain  

# ANSI escape codes for red text
RED = "\033[31m"
RESET = "\033[0m"  # Reset to default color

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")  # Connect to MongoDB (update if using a remote DB)
db = client["sub_enum"]  # Access the 'sub_enum' database
subdomain_collection = db["live_subdomains"]  # Access the 'live_subdomains' collection
injection_collection = db["injection_points"]  # New collection for storing filtered URLs

# Fetch subdomains from MongoDB that are related to the target domain
subdomains = [doc["subdomain"] for doc in subdomain_collection.find({"subdomain": {"$regex": f".*{target_domain}$", "$options": "i"}}, {"_id": 0, "subdomain": 1})]

# Add the main domain (target_domain) to the list of subdomains
subdomains.append(target_domain)

# Check if we retrieved subdomains
if not subdomains:
    print(f"No subdomains found for domain {target_domain} in the database.")
    exit()

# Function to get archived URLs for a subdomain using waybackurls
def get_archived_urls(subdomain):
    try:
        # Run waybackurls to get archived URLs for the subdomain
        result = subprocess.run(["waybackurls"], input=subdomain, capture_output=True, text=True, check=True)
        urls = result.stdout.splitlines()  # Split the result into individual URLs
        return urls
    except subprocess.CalledProcessError:
        print(f"Error retrieving archived URLs for {subdomain}")
        return []

# Function to filter URLs that contain query parameters (potential injection points)
def filter_injection_urls(urls):
    injection_patterns = [
        r"[?&][^=]+=[^&]+",  # Matches query parameters (e.g., ?param=value or &param=value)
        r"(?<=\?)\w+=\w+",  # Matches simple query parameters after ? (e.g., ?id=1)
        r"(?<=\?)\w+",  # Matches parameters without values (e.g., ?id)
        r"(?<=&)\w+=\w+"  # Matches additional parameters after & (e.g., &id=1)
    ]
    filtered_urls = []
    for url in urls:
        for pattern in injection_patterns:
            if re.search(pattern, url):
                filtered_urls.append(url)
                break
    return filtered_urls

# Loop through subdomains (including main domain) and fetch archived URLs, filtering for injection points
for subdomain in subdomains:
    print(f"{RED}Archived URLs for {subdomain} with potential injection points:{RESET}")
    urls = get_archived_urls(subdomain)
    filtered_urls = filter_injection_urls(urls)
    
    if filtered_urls:
        for url in filtered_urls:
            print(url)  # Print each filtered URL with potential injection points

        # Store the filtered URLs in MongoDB
        injection_collection.update_one(
            {"subdomain": subdomain},  # Match existing subdomain
            {"$set": {"urls": filtered_urls}},  # Update or set URLs
            upsert=True  # Insert if the subdomain doesn't exist
        )
    else:
        print("No URLs with potential injection points found.")
