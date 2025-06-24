import subprocess
import re
import logging
from urllib.parse import urlparse, parse_qs, urlencode

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

sensitive_js_keywords = ['config', 'auth', 'token', 'secret', 'key', 'admin']

injectable_params = [
    'id', 'uid', 'pid', 'ref', 'cat', 'cid', 'product', 'item', 'order', 'page', 'record', 'doc', 'post',
    'q', 'query', 'search', 'keyword', 'message', 'comment', 'feedback', 'input', 'email', 'name', 'title', 'desc', 'text',
    'cmd', 'exec', 'command', 'ping', 'host', 'ip', 'target', 'action', 'url', 'path', 'file', 'dir',
    'redirect', 'next', 'dest', 'destination', 'continue', 'return', 'goto',
    'include', 'template', 'folder', 'module', 'load'
]

redirect_keywords = ['redirect', 'url', 'next', 'dest', 'destination']

async def is_login_url(url):
    return "login" in url.lower()

async def is_sensitive_js(url):
    return url.endswith('.js') and any(keyword in url.lower() for keyword in sensitive_js_keywords)

async def is_injectable_url(url):
    parsed = urlparse(url)
    if not parsed.scheme.startswith("http"):
        return False
    if not parsed.query:
        return False
    qs = parse_qs(parsed.query)
    for param in injectable_params:
        if param in qs and qs[param] and all(v.strip() for v in qs[param]):
            return True
    return False

async def is_redirect_url(url):
    parsed = urlparse(url)
    if not parsed.query:
        return False
    qs = parse_qs(parsed.query)
    return any(param in qs for param in redirect_keywords)

async def enumerate_urls(subdomain_list):
    logger.info("[waybackurls] Starting waybackurls scan...")

    login_portals = set()
    sensitive_js_files = set()
    injectable_urls = set()
    redirect_urls = set()
    seen_normalized = set()  # For deduplication by path+param names

    for sub in subdomain_list:
        logger.info(f"[waybackurls] Scanning: {sub}")
        try:
            result = subprocess.run(['waybackurls', sub], capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                urls = set(result.stdout.strip().split('\n'))
                logger.info(f"[waybackurls] Found {len(urls)} URLs for {sub}")

                for url in urls:
                    url = url.strip()
                    if not url:
                        continue

                    if await is_login_url(url):
                        login_portals.add(url)

                    if await is_sensitive_js(url):
                        sensitive_js_files.add(url)

                    if await is_injectable_url(url):
                        parsed = urlparse(url)
                        query_params = parse_qs(parsed.query)
                        normalized_query = urlencode({k: "" for k in sorted(query_params)}, doseq=True)
                        normalized_url = parsed._replace(query=normalized_query).geturl()

                        if normalized_url not in seen_normalized:
                            seen_normalized.add(normalized_url)
                            injectable_urls.add(url)

                    if await is_redirect_url(url):
                        redirect_urls.add(url)
            else:
                logger.warning(f"[waybackurls] Error from waybackurls for {sub}: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error(f"[waybackurls] Timeout while scanning {sub}")
        except Exception as e:
            logger.error(f"[waybackurls] Exception while scanning {sub}: {e}")

    logger.info(f"[waybackurls] Finished scanning all subdomains.")
    logger.info(f"[summary] Login Pages ({len(login_portals)} found):")
    for url in login_portals:
        logger.info(f" - {url}")

    logger.info(f"[summary] Sensitive JS Files ({len(sensitive_js_files)} found):")
    for url in sensitive_js_files:
        logger.info(f" - {url}")

    logger.info(f"[summary] Injectable URLs ({len(injectable_urls)} found):")
    for url in injectable_urls:
        logger.info(f" - {url}")

    logger.info(f"[summary] Redirect URLs ({len(redirect_urls)} found):")
    for url in redirect_urls:
        logger.info(f" - {url}")

    archive_urls = [{
        "login_portals": list(login_portals),
        "sensitive_js_files": list(sensitive_js_files),
        "injectable_urls": list(injectable_urls),
        "redirect_urls": list(redirect_urls)
    }]
    return archive_urls
