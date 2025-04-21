import requests
import logging
from datetime import datetime
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

WAF_SIGNATURES = [
    "cf-ray",  # Cloudflare
    "x-sucuri-id",  # Sucuri
    "server: cloudflare",  # Cloudflare
    "x-powered-by: wpengine",  # WP Engine
    "x-waf",  # Custom WAF signature
    "via: 1.1 varnish",  # Varnish
]

def detect_waf(subdomain: str, timeout: int = 5) -> dict:
    try:
        logger.info(f"[WAF Check] Checking WAF for: {subdomain}")

        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(f"http://{subdomain}", headers=headers, timeout=timeout)

        if response.status_code == 200:
            waf_detected = False
            for signature in WAF_SIGNATURES:
                if signature.lower() in response.text.lower() or signature.lower() in response.headers:
                    waf_detected = True
                    break

            return {
                'subdomain': subdomain,
                'has_waf': waf_detected,
                'status_code': response.status_code,
                'headers': response.headers
            }
        else:
            logger.warning(f"[WAF Check] Received non-200 status code for {subdomain}: {response.status_code}")

    except requests.exceptions.RequestException as e:
        logger.warning(f"[WAF Check] Request failed for {subdomain}: {e}")

    return {
        'subdomain': subdomain,
        'has_waf': False,
        'status_code': None,
        'headers': None
    }

async def enumerate_waf(subdomains: list[str]) -> list[dict]:
    waf_details = []

    tasks = [asyncio.to_thread(detect_waf, sub) for sub in subdomains]
    results = await asyncio.gather(*tasks)

    for info in results:
        waf_details.append(info)
        if info['has_waf']:
            logger.info(f" Subdomain: {info['subdomain']} has a WAF.")
        else:
            logger.info(f" Subdomain: {info['subdomain']} does not have a WAF.")

    return waf_details
