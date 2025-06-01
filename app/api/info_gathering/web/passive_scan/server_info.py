import aiohttp
import asyncio
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Fetch server-related headers
async def fetch_server_header(session, subdomain):
    for scheme in ["http", "https"]:
        try:
            url = f"{scheme}://{subdomain}"
            async with session.get(url, timeout=10, allow_redirects=True) as response:
                headers = response.headers
                server = headers.get("Server", "")
                powered_by = headers.get("X-Powered-By", "")
                via = headers.get("Via", "")
                return subdomain, server, powered_by, via
        except Exception as e:
            logger.warning(f"[Server Header] Error fetching {scheme.upper()} headers for {subdomain}: {e}")
    return subdomain, "", "", ""

# Parse server product and version
async def parse_server_info(header: str):
    if not header:
        return "Unknown", "Unknown"

    match = re.match(r"([^\s/]+)(?:/([\d\.]+))?", header)
    if match:
        product = match.group(1)
        version = match.group(2) if match.group(2) else "Unknown"
        return product, version
    return header, "Unknown"

# Guess OS and version from all headers
async def guess_os(*headers):
    combined = " ".join(h.lower() for h in headers if h)

    if "windows" in combined:
        version = re.search(r"windows\s?(server\s?\d+|[\d\.]+)?", combined)
        return "Windows", version.group(1) if version and version.group(1) else "Unknown"

    elif any(x in combined for x in ["ubuntu", "debian", "centos", "red hat", "linux", "unix"]):
        version = re.search(r"(ubuntu|debian|centos|red hat)[\s/]*([\d\.]+)?", combined)
        os_name = version.group(1).capitalize() if version else "Linux/Unix"
        os_version = version.group(2) if version and version.group(2) else "Unknown"
        return os_name, os_version

    return "Unknown", "Unknown"

# Scan a single subdomain
async def scan_subdomain(session, subdomain):
    sub, server_header, powered_by, via = await fetch_server_header(session, subdomain)
    all_headers = [server_header, powered_by, via]

    main_header = next((h for h in all_headers if h), "")
    product, version = await parse_server_info(main_header)
    os_name, os_version = await guess_os(*all_headers)

    return {
        "subdomain": sub,
        "server": f"{product}/{version}" if version != "Unknown" else product,
        "os": f"{os_name} {os_version}" if os_version != "Unknown" else os_name,
    }

# Run scan for all subdomains
async def final_result(subdomains):
    async with aiohttp.ClientSession() as session:
        tasks = [scan_subdomain(session, sub) for sub in subdomains]
        results = await asyncio.gather(*tasks)
        return results
