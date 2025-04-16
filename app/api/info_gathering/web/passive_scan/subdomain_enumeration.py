import asyncio
import httpx
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
            logger.warning(f"Error running {command[0]}: {stderr.decode().strip()}")
            return []
    except FileNotFoundError:
        logger.error(f"{command[0]} not found. Make sure it's installed and in your PATH.")
        return []


async def check_live_subdomains(subdomains):
    """Check which subdomains are live using HTTP requests."""
    live_subdomains = []
    async with httpx.AsyncClient() as client:
        tasks = [client.get(f"http://{sub}", timeout=5) for sub in subdomains]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for subdomain, response in zip(subdomains, responses):
            if isinstance(response, httpx.Response) and response.status_code == 200:
                live_subdomains.append(subdomain)
            elif isinstance(response, Exception):
                logger.debug(f"Error checking {subdomain}: {response}")
    return live_subdomains


async def run_subdomain_enum(domain: str) -> list:
    """Run subdomain enumeration asynchronously and return only live subdomains."""
    domain = domain.strip().lower().lstrip("www.")
    logger.info(f"Starting subdomain enumeration for: {domain}")

    tools = [
        ['findomain', '-t', domain],
        ['subfinder', '-d', domain],
        ['assetfinder', '--subs-only', domain]
    ]

    results = await asyncio.gather(*(run_tool(tool) for tool in tools))
    all_subdomains = set(sub for result in results for sub in result if sub.endswith(domain))

    logger.info(f"Discovered {len(all_subdomains)} unique subdomains (before live check).")

    live_subdomains = await check_live_subdomains(all_subdomains)

    logger.info(f"{len(live_subdomains)} live subdomains found.")
    for sub in live_subdomains:
        logger.info(f" - {sub}")

    return live_subdomains
