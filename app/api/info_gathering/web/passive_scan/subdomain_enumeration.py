import asyncio
import httpx
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Limit the number of concurrent HTTP requests
semaphore = asyncio.Semaphore(50)

async def run_tool(command):
    """Run a subdomain enumeration tool asynchronously and return the results."""
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()   # process.communicate() waits until the program exits and then returns a tuple of bytes: what was written to stdout and to stderr.
        if process.returncode == 0:
            return stdout.decode().splitlines()
        else:
            logger.warning(f"Error running {command[0]}: {stderr.decode().strip()}")
            return []
    except FileNotFoundError:
        logger.error(f"{command[0]} not found. Make sure it's installed and in your PATH.")
        return []

async def fetch(client, url, subdomain):
    """Try to fetch a URL and return the subdomain if it is live."""
    async with semaphore:
        try:
            response = await client.get(url)
            if response.status_code < 400:
                return subdomain
        except Exception as e:
            logger.debug(f"{url} failed: {e}")
    return None

async def check_live_subdomains(subdomains):
    """Check which subdomains are live using both HTTP and HTTPS."""
    live_subdomains = set()
    async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
        tasks = []
        for sub in subdomains:
            tasks.append(fetch(client, f"http://{sub}", sub))
            tasks.append(fetch(client, f"https://{sub}", sub))

        results = await asyncio.gather(*tasks)
        live_subdomains = {r for r in results if r}

    return list(live_subdomains)

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

