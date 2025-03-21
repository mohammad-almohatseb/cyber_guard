import asyncio
import httpx
from app.api.requests.request_flow import target_url
from utils import get_domain_from_url
from models.information import InfoGatheringModel, Subdomain  

try:
    domain = get_domain_from_url(target_url)
    print(f"Extracted domain: {domain}")
except ValueError as e:
    print(f"Error: {e}")
    exit(1)

async def run_tool(command):
    """Run a subdomain enumeration tool asynchronously and return the results."""
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode == 0:
            return stdout.decode().splitlines()
        else:
            print(f"Error running {command[0]}: {stderr.decode()}")
            return []
    except FileNotFoundError:
        print(f"Error: {command[0]} not found. Ensure it's installed.")
        return []

async def check_live_subdomains(subdomains):
    """Check which subdomains are live using HTTP requests."""
    live_subdomains = []
    async with httpx.AsyncClient() as client:
        tasks = [client.get(f"http://{subdomain}", timeout=5) for subdomain in subdomains]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for subdomain, response in zip(subdomains, responses):
            if isinstance(response, httpx.Response) and response.status_code == 200:
                live_subdomains.append(subdomain)
    return live_subdomains

async def store_subdomains(target_domain, live_subdomains):
    """Store live subdomains in the InfoGatheringModel."""
    # Retrieve or create the InfoGatheringModel document
    info_gathering = await InfoGatheringModel.find_one({"target": target_domain})

    if not info_gathering:
        info_gathering = InfoGatheringModel(
            target=target_domain,
            target_type="web",  # Adjust if this is network
        )

    # Store the live subdomains
    info_gathering.subdomains = [Subdomain(subdomain=sub) for sub in live_subdomains]

    # Save the document to the database
    await info_gathering.save()
    print(f"Live subdomains stored in database for domain: {target_domain}")

async def run_subdomain_enum(target_domain) -> list:
    """Run subdomain enumeration asynchronously with multiple tools."""
    tools = [
        ['findomain', '-t', target_domain],
        ['subfinder', '-d', target_domain],
        ['assetfinder', '--subs-only', target_domain]
    ]

    # Run all tools in parallel
    results = await asyncio.gather(*(run_tool(tool) for tool in tools))

    # Merge results and remove duplicates
    unique_subdomains = set(sub for result in results for sub in result)

    live_subdomains = await check_live_subdomains(unique_subdomains)

    await store_subdomains(target_domain, live_subdomains)

    for sub in live_subdomains:
        print(sub)

    return live_subdomains

if __name__ == "__main__":
    asyncio.run(run_subdomain_enum(domain))
