import aiohttp
import asyncio
import logging
import shlex
import asyncio.subprocess

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Fetch server header
async def fetch_server_header(session, subdomain):
    try:
        url = f"http://{subdomain}"
        async with session.get(url, timeout=10) as response:
            server = response.headers.get("Server", "")
            return subdomain, server
    except Exception as e:
        logger.warning(f"[Server Header] Error fetching server header for {subdomain}: {e}")
        return subdomain, ""


async def parse_server_info(server_header: str):
    if not server_header:
        return ("Unknown", "Unknown")

    parts = server_header.split("/")
    if len(parts) == 2:
        return parts[0], parts[1]
    else:
        return server_header, "Unknown"


async def guess_os(server: str):
    server = server.lower()
    if "win" in server:
        return "Windows"
    elif "unix" in server or "ubuntu" in server or "debian" in server or "linux" in server:
        return "Linux/Unix"
    else:
        return "Unknown"


async def fetch_cves(product: str, version: str):
    try:
        query = f"{product}+{version}" if version != "Unknown" else product
        url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={query}"
        logger.info(f"[CVEs] Created CVE search URL: {url}")
        return url
    except Exception as e:
        logger.warning(f"[CVEs] Failed to create CVE search URL for {product}/{version}: {e}")
        return ""


async def scan_subdomain(session, subdomain):
    sub, server_header = await fetch_server_header(session, subdomain)
    product, version = parse_server_info(server_header)
    os_guess = guess_os(server_header)
    cve_url = await fetch_cves(product, version)

    return {
        "subdomain": sub,
        "server": f"{product}/{version}" if version != "Unknown" else product,
        "os": os_guess,
        "cve_url": cve_url,
    }


async def final_result(subdomains):
    async with aiohttp.ClientSession() as session:
        tasks = [scan_subdomain(session, sub) for sub in subdomains]
        results = await asyncio.gather(*tasks)

        for res in results:
            logger.info(f"\nSubdomain: {res['subdomain']}")
            logger.info(f"Server: {res['server']}")
            logger.info(f"OS: {res['os']}")
            logger.info(f"CVE URL: {res['cve_url'] if res['cve_url'] else 'No CVE URL generated'}\n")

        return results
