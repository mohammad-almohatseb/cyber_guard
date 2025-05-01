import requests
import logging
from datetime import datetime
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-XSS-Protection",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
]


REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
    "Referer": "https://example.com",
    "X-Forwarded-For": "203.0.113.1",
    "X-Real-IP": "203.0.113.1",
    "Authorization": "Bearer dummy-token",
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Accept-Encoding": "gzip, deflate, br",
    "Origin": "https://example.com",
    "X-Custom-Test-Header": "CyberScanTest"
}

def gather_header_info(subdomain: str, timeout: int = 5) -> dict:
    url = f"https://{subdomain}"
    logger.info(f"[Header Scan] Checking headers for: {url}")

    try:
        response = requests.get(url, headers=REQUEST_HEADERS, timeout=timeout, allow_redirects=True)

        security_headers_found = {}
        for header in SECURITY_HEADERS:
            security_headers_found[header] = response.headers.get(header)

        
        observed_response_headers = {
            "Set-Cookie": response.headers.get("Set-Cookie"),
            "Server": response.headers.get("Server"),
            "Content-Type": response.headers.get("Content-Type"),
        }

        return {
            "subdomain": subdomain,
            "status_code": response.status_code,
            "security_headers": security_headers_found,
            "observed_headers": observed_response_headers,
            "date_checked": datetime.utcnow().isoformat()
        }

    except requests.exceptions.RequestException as e:
        logger.warning(f"[Header Scan] Request failed for {subdomain}: {e}")
        return {
            "subdomain": subdomain,
            "status_code": None,
            "security_headers": None,
            "observed_headers": None,
            "date_checked": datetime.utcnow().isoformat()
        }

async def scan_https_headers(subdomains: list[str]) -> list[dict]:
    results = []
    tasks = [asyncio.to_thread(gather_header_info, sub) for sub in subdomains]
    all_results = await asyncio.gather(*tasks)

    for result in all_results:
        logger.info(f"\n Subdomain: {result['subdomain']} - Status: {result['status_code']}")
        
        if result["security_headers"]:
            logger.info(" Security Headers:")
            for key, value in result["security_headers"].items():
                logger.info(f"  - {key}: {value}")
        
        if result["observed_headers"]:
            logger.info(" Observed Headers:")
            for key, value in result["observed_headers"].items():
                logger.info(f"  - {key}: {value}")

        results.append(result)

    return results
