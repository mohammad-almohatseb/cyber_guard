import subprocess
import re
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

sensitive_js_keywords = ['config', 'auth', 'token', 'secret', 'key', 'admin']
injectable_params = ['id', 'q', 'search', 'query', 'page', 'input', 'ref', 'cat']
redirect_keywords = ['redirect', 'url', 'next', 'dest', 'destination']

async def is_login_url(url):
    return "login" in url.lower()

async def is_sensitive_js(url):
    return url.endswith('.js') and any(keyword in url.lower() for keyword in sensitive_js_keywords)

async def is_injectable_url(url):
    return any(re.search(rf'[\?&]{param}=', url, re.IGNORECASE) for param in injectable_params)

async def is_redirect_url(url):
    return any(re.search(rf'[\?&]{param}=', url, re.IGNORECASE) for param in redirect_keywords)

async def enumerate_urls(subdomain_list):
    logger.info("[waybackurls] Starting waybackurls scan...")
    login_portals = []
    sensitive_js_files = []
    injectable_urls = []
    redirect_urls = []

    for sub in subdomain_list:
        logger.info(f"[waybackurls] Scanning: {sub}")
        try:
            result = subprocess.run(['waybackurls', sub], capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                urls = result.stdout.strip().split('\n')
                logger.info(f"[waybackurls] Found {len(urls)} URLs for {sub}")
                for url in urls:
                    url = url.strip()
                    if not url:
                        continue
                    if await is_login_url(url):  
                        login_portals.append(url)
                    if await is_sensitive_js(url):  
                        sensitive_js_files.append(url)
                    if await is_injectable_url(url):  
                        injectable_urls.append(url)
                    if await is_redirect_url(url):  
                        redirect_urls.append(url)
            else:
                logger.warning(f"[waybackurls] Error from waybackurls for {sub}: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error(f"[waybackurls] Timeout while scanning {sub}")
        except Exception as e:
            logger.error(f"[waybackurls] Exception while scanning {sub}: {e}")

    logger.info(f"[waybackurls] Finished scanning all subdomains.")
    logger.info(f"[summary] Login Pages ({len(login_portals)} found):")
    for url in login_portals:
        logger.info(f"  - {url}")

    logger.info(f"[summary] Sensitive JS Files ({len(sensitive_js_files)} found):")
    for url in sensitive_js_files:
        logger.info(f"  - {url}")

    logger.info(f"[summary] Injectable URLs ({len(injectable_urls)} found):")
    for url in injectable_urls:
        logger.info(f"  - {url}")

    logger.info(f"[summary] Redirect URLs ({len(redirect_urls)} found):")
    for url in redirect_urls:
        logger.info(f"  - {url}")

    archive_urls = []
    archive_urls.append({
        "login_portals": login_portals,
        "sensitive_js_files": sensitive_js_files,
        "injectable_urls": injectable_urls,
        "redirect_urls": redirect_urls
    })

    return archive_urls
