import httpx
import logging
import asyncio
from urllib.parse import urljoin

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Top 100 common admin and sensitive paths (trimmed for brevity)
COMMON_PATHS = [
    # Standard Entry Points
    "/robots.txt", "/humans.txt", "/sitemap.xml", "/crossdomain.xml",

    # Authentication & Login
    "/login", "/signin", "/signup", "/logout", "/register",
    "/admin", "/admin/login", "/admincp", "/admin-panel", "/administrator", "/adminconsole",
    "/adminarea", "/admin_login", "/adminsignin", "/signin-admin", "/admin-user", "/admin-users",
    "/user", "/users", "/useradmin", "/account", "/accounts", "/auth", "/authenticate",

    # Dashboard & Panels
    "/dashboard", "/cp", "/controlpanel", "/control", "/backend", "/manage", "/settingsadmin",
    "/settings", "/config", "/configuration", "/webadmin", "/cms", "/panel", "/superadmin", "/mod", "/moderator",

    # WordPress
    "/wp-admin", "/wp-login", "/wp-content", "/wp-includes",

    # File Managers / Uploads
    "/upload", "/uploads", "/download", "/downloads", "/files", "/filemanager", "/ftp",

    # Databases & Tools
    "/db", "/database", "/phpmyadmin", "/adminer", "/websql",

    # Dev & Debug
    "/debug", "/debugbar", "/test", "/tests", "/staging", "/qa", "/dev", "/development", "/build",
    "/logs", "/log", "/error", "/errors", "/trace", "/traceroute", "/status", "/health", "/metrics",

    # APIs
    "/api", "/api/v1", "/api/v2", "/graphql", "/rest", "/swagger", "/openapi",

    # Source and Includes
    "/src", "/source", "/includes", "/include", "/vendor", "/composer.lock", "/package.json",

    # Temp and Backup
    "/temp", "/tmp", "/backup", "/backups", "/bak", "/old", "/archive", "/restore", "/.old", "/.bak",

    # Installers & Setup
    "/setup", "/install", "/installation", "/setup.php", "/install.php",

    # Config Files
    "/webconfig", "/web.config", "/config.json", "/config.php", "/conf", "/.env", "/.git", "/.svn",

    # Hidden/Secret/Internal
    "/private", "/secret", "/hidden", "/internal", "/intranet", "/secure",

    # Staff & Support
    "/staff", "/support", "/help", "/contact", "/faq", "/tickets",

    # Sessions & Tokens
    "/session", "/sessions", "/token", "/csrf", "/auth-token",

    # Other Admin Variants
    "/adminarea", "/admin_console", "/admininterface", "/admin/dashboard", "/admin/home",

    # Misc
    "/monitor", "/monitoring", "/analytics", "/reports", "/report", "/doc", "/docs", "/documentation"
]



async def check_path(client: httpx.AsyncClient, subdomain: str, path: str) -> dict:
    url = urljoin(f"https://{subdomain}", path)
    try:
        response = await client.get(url, timeout=5, follow_redirects=True)
        if response.status_code < 400:
            logger.info(f"[+] Found: {url} ({response.status_code})")
            return {"path": path, "status": response.status_code, "url": url}
    except httpx.RequestError as e:
        logger.warning(f"[-] Error on {url}: {e}")
    return None


async def enumerate_directories(subdomain: str) -> list[dict]:
    logger.info(f"[Directory Enum] Starting on: {subdomain}")
    results = []

    async with httpx.AsyncClient(verify=False) as client:
        tasks = [check_path(client, subdomain, path) for path in COMMON_PATHS]
        raw_results = await asyncio.gather(*tasks)

    for result in raw_results:
        if result:
            results.append(result)

    logger.info(f"[Directory Enum] Completed for: {subdomain}\n")
    return results


async def enum_dir_on_subdomains(subdomains: list[str]) -> list[str]:
    final_urls = []
    tasks = [enumerate_directories(sub) for sub in subdomains]
    all_results = await asyncio.gather(*tasks)

    for paths in all_results:
        for result in paths:
            if result and "url" in result:
                final_urls.append(result["url"])
                
    return final_urls




