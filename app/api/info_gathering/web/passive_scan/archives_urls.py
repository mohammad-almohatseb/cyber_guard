import asyncio
import subprocess
import logging
from urllib.parse import urlparse, parse_qs, urlencode

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Expanded keyword lists
sensitive_js_keywords = ['config', 'auth', 'token', 'secret', 'key', 'admin']

injectable_params = [
    'id', 'uid', 'pid', 'ref', 'cat', 'cid', 'product', 'item', 'order', 'page', 'record', 'doc', 'post',
    'q', 'query', 'search', 'keyword', 'message', 'comment', 'feedback', 'input', 'email', 'name', 'title', 'desc', 'text',
    'cmd', 'exec', 'command', 'ping', 'host', 'ip', 'target', 'action', 'url', 'path', 'file', 'dir',
    'redirect', 'next', 'dest', 'destination', 'continue', 'return', 'goto',
    'include', 'template', 'folder', 'module', 'load'
]

redirect_keywords = [
    'redirect', 'url', 'next', 'dest', 'destination', 'continue', 'return', 'goto',
    'redir', 'redirect_url', 'redirect_uri', 'redirect_to', 'back', 'callback',
    'ret', 'out', 'navigation', 'ref', 'forward', 'jump', 'move', 'target', 'view', 'path'
]

redirect_path_keywords = ['redirect', 'goto', 'jump', 'forward', 'return', 'out', 'nav']


# Category checks
async def is_login_url(url):
    return "login" in url.lower()

async def is_sensitive_js(url):
    return url.endswith('.js') and any(keyword in url.lower() for keyword in sensitive_js_keywords)

async def is_injectable_url(url):
    parsed = urlparse(url)
    if not parsed.scheme.startswith("http") or not parsed.query:
        return False
    qs = parse_qs(parsed.query)   # is dictionary like {'id': ['5'], 'sort': ['asc']}

    return any(param in qs and all(v.strip() for v in qs[param]) for param in injectable_params)  




async def is_redirect_url(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)   
    # Check query parameters
    for param, values in qs.items():
        if param.lower() in redirect_keywords:
            return True
        for value in values:
            if value.startswith(('http://', 'https://', '/')) or '.' in value:
                if any(keyword in param.lower() for keyword in redirect_keywords):
                    return True

    # Check path patterns
    if any(part in parsed.path.lower() for part in redirect_path_keywords):
        return True

    return False

# Helper to normalize ..to give me the injectable urls without duplicates and to show only the parametres without it's value like "https://x.com/product?id=&sort="
def normalize_url(url):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    normalized_query = urlencode({k: "" for k in sorted(query_params)}, doseq=True)   
    return parsed._replace(query=normalized_query).geturl()

# Process each URL
async def process_url(url, seen_normalized, results):
    try:
        url = url.strip()
        if not url:
            return

        if await is_login_url(url):
            results['login_portals'].add(url)

        if await is_sensitive_js(url):
            results['sensitive_js_files'].add(url)

        if await is_injectable_url(url):
            normalized = normalize_url(url)
            if normalized not in seen_normalized:
                seen_normalized.add(normalized)
                results['injectable_urls'].add(url)

        if await is_redirect_url(url):
            results['redirect_urls'].add(url)

    except Exception as e:
        logger.warning(f"[process_url] Error processing {url}: {e}")

# Run waybackurls for one subdomain
async def scan_subdomain(sub, seen_normalized, results, timeout=120):
    logger.info(f"[waybackurls] Scanning: {sub}")
    try:
        proc = await asyncio.create_subprocess_exec(
            'waybackurls', sub,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.error(f"[waybackurls] Timeout while scanning {sub}")
            return

        if proc.returncode != 0:
            logger.warning(f"[waybackurls] Error for {sub}: {stderr.decode().strip()}")
            return

        urls = set(stdout.decode().strip().split('\n'))
        logger.info(f"[waybackurls] Found {len(urls)} URLs for {sub}")

        tasks = [process_url(url, seen_normalized, results) for url in urls if url]
        await asyncio.gather(*tasks)

    except Exception as e:
        logger.error(f"[waybackurls] Exception while scanning {sub}: {e}")

# Main orchestration
async def enumerate_urls(subdomain_list):
    logger.info("[waybackurls] Starting scan...")

    results = {
        "login_portals": set(),
        "sensitive_js_files": set(),
        "injectable_urls": set(),
        "redirect_urls": set()
    }

    seen_normalized = set()
    scan_tasks = [scan_subdomain(sub, seen_normalized, results) for sub in subdomain_list]
    await asyncio.gather(*scan_tasks)

    for category, urls in results.items():
        logger.info(f"[summary] {category.replace('_', ' ').title()} ({len(urls)} found):")
        for url in urls:
            logger.info(f" - {url}")

    return [{
        "login_portals": list(results['login_portals']),
        "sensitive_js_files": list(results['sensitive_js_files']),
        "injectable_urls": list(results['injectable_urls']),
        "redirect_urls": list(results['redirect_urls'])
    }]
