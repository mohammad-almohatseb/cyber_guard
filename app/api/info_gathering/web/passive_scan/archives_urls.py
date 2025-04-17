from InfoGather import subdomains
import subprocess
import re
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

subdomain_list = subdomains 

sensitive_js_keywords = ['config', 'auth', 'token', 'secret', 'key', 'admin']
injectable_params = ['id', 'q', 'search', 'query', 'page', 'input', 'ref' , 'cat']
redirect_keywords = ['redirect', 'url', 'next', 'dest', 'destination']

def is_login_url(url):
    return "login" in url.lower()

def is_sensitive_js(url):
    return url.endswith('.js') and any(keyword in url.lower() for keyword in sensitive_js_keywords)

def is_injectable_url(url):
    return any(re.search(rf'[\?&]{param}=', url, re.IGNORECASE) for param in injectable_params)

def is_redirect_url(url):
    return any(re.search(rf'[\?&]{param}=', url, re.IGNORECASE) for param in redirect_keywords)

def enumerate_urls(subdomain_list):
   
    login_portals = []
    sensitive_js_files = []
    injectable_urls = []
    redirect_urls = []

    for sub in subdomain_list:
        logger.info(f"[waybackurls] Scanning: {sub}")
        try:
            result = subprocess.run(['waybackurls', sub], capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                urls = result.stdout.strip().split('\n')
                for url in urls:
                    if is_login_url(url):
                        login_portals.append(url)
                    if is_sensitive_js(url):
                        sensitive_js_files.append(url)
                    if is_injectable_url(url):
                        injectable_urls.append(url)
                    if is_redirect_url(url):
                        redirect_urls.append(url)
            else:
                logger.warning(f"[waybackurls] Error from waybackurls for {sub}: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error(f"[waybackurls] Timeout while scanning {sub}")
        except Exception as e:
            logger.error(f"[waybackurls] Exception while scanning {sub}: {e}")

    logger.info(f"[waybackurls] Finished scanning all subdomains.")
    logger.info(f"[summary] Login Pages: {len(login_portals)}")
    logger.info(f"[summary] Sensitive JS Files: {len(sensitive_js_files)}")
    logger.info(f"[summary] Injectable URLs: {len(injectable_urls)}")
    logger.info(f"[summary] Redirect URLs: {len(redirect_urls)}")

    return login_portals, sensitive_js_files, injectable_urls, redirect_urls

login_portals, sensitive_js_files, injectable_urls, redirect_urls = enumerate_urls(subdomain_list)
