import httpx
from bs4 import BeautifulSoup
import difflib
import re
import logging
import random
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Mozilla/5.0 (Android 11; Mobile; rv:89.0)"
]

PAYLOADS = [
    {"param": "cmd", "payload": "; whoami", "expected_vulnerability": "CMDI"},
    {"param": "id", "payload": "' OR 1=1 --", "expected_vulnerability": "SQLI"},
    {"param": "q", "payload": "\"><script>alert(1)</script>", "expected_vulnerability": "XSS"},
    {"param": "q", "payload": "\"><img src=x onerror=alert(1)>", "expected_vulnerability": "XSS"},
]

def inject_payload_to_url(url: str, param: str, payload: str):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = payload
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

async def process_payload(client, full_url, param, item):
    payload = item["payload"]
    vuln_type = item["expected_vulnerability"]

    normal_url = inject_payload_to_url(full_url, param, "normalinput")
    test_url = inject_payload_to_url(full_url, param, payload)

    headers = {
        "User-Agent": random.choice(USER_AGENTS)
    }

    try:
        normal_resp = await client.get(normal_url, headers=headers)
        test_resp = await client.get(test_url, headers=headers)

        soup = BeautifulSoup(test_resp.text, "html.parser")
        text_only = soup.get_text()

        reflected = payload in text_only or bool(re.search(re.escape(payload), test_resp.text, re.IGNORECASE))
        error_signs = bool(re.search(r"(error|exception|traceback|syntax)", test_resp.text, re.IGNORECASE))
        encoded_payload = re.sub(r"[^a-zA-Z0-9]", "", payload)
        encoded_found = encoded_payload in re.sub(r"[^a-zA-Z0-9]", "", test_resp.text)

        diff = list(difflib.unified_diff(
            normal_resp.text.splitlines(),
            test_resp.text.splitlines()
        ))
        diff_found = any(payload in line for line in diff)

        return {
            "url": full_url,
            "payload": payload,
            "param": param,
            "reflected": reflected,
            "encoded_match": encoded_found,
            "error_signs": error_signs,
            "diff_match": diff_found,
            "status_code": test_resp.status_code,
            "expected_vulnerability": vuln_type if reflected else None
        }

    except Exception as e:
        return {"url": full_url, "param": param, "payload": payload, "error": str(e)}

async def scan_input_validation(injectable_urls: list) -> list:
    results = []
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            tasks = []

            for full_url in injectable_urls:
                parsed = urlparse(full_url)
                query = parse_qs(parsed.query)

                if not query:
                    logger.warning(f"No injectable parameter found in URL: {full_url}")
                    continue

                for param in query:
                    logger.info(f"Scanning {full_url} using param={param}")
                    for item in PAYLOADS:
                        if item["param"] == param:
                            tasks.append(process_payload(client, full_url, param, item))

            # Run tasks with concurrency
            semaphore = asyncio.Semaphore(10)

            async def sem_task(task):
                async with semaphore:
                    return await task

            raw_results = await asyncio.gather(*(sem_task(task) for task in tasks))

            for r in raw_results:
                results.append(r)

        return results

    except Exception as e:
        return [{"error": f"Fatal error in scanning URLs: {str(e)}"}]
