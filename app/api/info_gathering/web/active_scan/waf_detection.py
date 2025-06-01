import requests
import logging
import asyncio

# Setup logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Dictionary of WAF signatures and names
WAF_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "server: cloudflare": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-powered-by: wpengine": "WP Engine",
    "x-waf": "Generic WAF",
    "x-akamai-transformed": "Akamai",
    "x-cdn": "Generic CDN",
    "via: 1.1 varnish": "Varnish",
    "x-imunify360": "Imunify360",
}

# Detect WAF for a single subdomain
def detect_waf(subdomain: str, timeout: int = 5) -> dict:
    try:
        logger.info(f"[WAF Check] Checking WAF for: {subdomain}")
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(f"https://{subdomain}", headers=headers, timeout=timeout)

        if response.status_code == 200:
            headers_combined = "\n".join(f"{k.lower()}: {v.lower()}" for k, v in response.headers.items())

            for signature, waf_name in WAF_SIGNATURES.items():
                if signature.lower() in headers_combined or signature.lower() in response.text.lower():
                    return {
                        'subdomain': subdomain,
                        'has_waf': True,
                        'waf_name': waf_name,
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    }

    except requests.exceptions.RequestException as e:
        logger.warning(f"[WAF Check] Request failed for {subdomain}: {e}")

    return {
        'subdomain': subdomain,
        'has_waf': False,
        'waf_name': None,
        'status_code': None,
        'headers': None
    }

# Asynchronously enumerate WAFs on a list of subdomains
async def enumerate_waf(subdomains: list[str]) -> list[dict]:
    waf_details = []
    tasks = [asyncio.to_thread(detect_waf, sub) for sub in subdomains]
    results = await asyncio.gather(*tasks)

    for info in results:
        waf_details.append(info)
        if info['has_waf']:
            logger.info(f" {info['subdomain']} has a WAF: {info['waf_name']}")
        else:
            logger.info(f" {info['subdomain']} does NOT have a WAF.")

    return waf_details


