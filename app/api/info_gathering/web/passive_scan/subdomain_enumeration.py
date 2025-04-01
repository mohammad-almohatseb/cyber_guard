import asyncio
import httpx
from app.api.requests.request_flow import target_url
from utils import get_domain_from_url



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

async def run_subdomain_enum(domain=None) -> list:
    """Run subdomain enumeration asynchronously with multiple tools."""
    
    # Use target_url if domain is not provided
    if domain is None:
        domain = target_url  

    try:
        domain = get_domain_from_url(domain)  
        print(f"Extracted domain: {domain}")
    except ValueError as e:
        print(f"Error: {e}")
        return []

    tools = [
        ['findomain', '-t', domain],
        ['subfinder', '-d', domain],
        ['assetfinder', '--subs-only', domain]
    ]

    results = await asyncio.gather(*(run_tool(tool) for tool in tools))
    unique_subdomains = set(sub for result in results for sub in result)
    live_subdomains = await check_live_subdomains(unique_subdomains)

    for sub in live_subdomains:
        print(sub)

    return live_subdomains


if __name__ == "__main__":
    asyncio.run(run_subdomain_enum()) 