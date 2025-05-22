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

# Guess OS from all headers
async def guess_os(*headers):
    combined = " ".join(h.lower() for h in headers if h)
    if any(x in combined for x in ["win32", "windows", "asp.net"]):
        return "Windows"
    elif any(x in combined for x in ["unix", "ubuntu", "debian", "linux", "centos", "apache", "nginx"]):
        return "Linux/Unix"
    else:
        return "Unknown"

# Generate a CVE search URL
async def fetch_cves(product: str, version: str):
    try:
        query = f"{product}+{version}" if version != "Unknown" else product
        url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={query}"
        logger.info(f"[CVEs] Created CVE search URL: {url}")
        return url
    except Exception as e:
        logger.warning(f"[CVEs] Failed to create CVE search URL for {product}/{version}: {e}")
        return ""

# Scan a single subdomain
async def scan_subdomain(session, subdomain):
    sub, server_header, powered_by, via = await fetch_server_header(session, subdomain)
    all_headers = [server_header, powered_by, via]

    # Choose the most useful header for version info
    main_header = next((h for h in all_headers if h), "")
    product, version = await parse_server_info(main_header)
    os_guess = await guess_os(*all_headers)
    cve_url = await fetch_cves(product, version)

    return {
        "subdomain": sub,
        "server": f"{product}/{version}" if version != "Unknown" else product,
        "os": os_guess,
        "cve_url": cve_url,
    }

# Run scan for all subdomains
async def final_result(subdomains):
    async with aiohttp.ClientSession() as session:
        tasks = [scan_subdomain(session, sub) for sub in subdomains]
        results = await asyncio.gather(*tasks)

       

        return results


