import subprocess
import dns.resolver
import logging
import tldextract
from urllib.parse import urlparse

logger = logging.getLogger("tech_info")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


def run_nmap(subdomain):
    logger.info(f"Running Nmap on {subdomain}")
    try:
        output = subprocess.check_output(["nmap", "-sV", "-Pn", subdomain])
        logger.info("Nmap scan completed successfully")
        return output.decode()
    except Exception as e:
        logger.warning(f"Nmap error on {subdomain}: {e}")
        return ""


def run_gau(subdomain):
    logger.info(f"Running gau to get archived URLs for {subdomain}")
    try:
        output = subprocess.check_output(["gau", subdomain])
        logger.info("gau output retrieved")
        return output.decode().splitlines()
    except Exception as e:
        logger.warning(f"gau error on {subdomain}: {e}")
        return []


def get_mx_records(subdomain):
    logger.info(f"Getting MX records for {subdomain}")
    try:
        answers = dns.resolver.resolve(subdomain, "MX")
        mx_records = [str(r.exchange) for r in answers]
        logger.info(f"Found MX records: {mx_records}")
        return mx_records
    except Exception as e:
        logger.warning(f"MX record error on {subdomain}: {e}")
        return []


def extract_tech_info_from_nmap_line(line):
    parts = line.split()
    if len(parts) >= 3:
        service = parts[2]
        version = " ".join(parts[3:]) if len(parts) > 3 else ""
        return f"{service} {version}".strip(), line.strip()
    return None, None


def get_third_party_js(js_urls, domain_root):
    third_party_urls = []
    for url in js_urls:
        if not url.startswith("http"):
            url = "http://" + url
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc
            if not netloc:
                continue
            url_root = tldextract.extract(netloc).registered_domain
            if url_root and url_root != domain_root:
                third_party_urls.append(url)
        except Exception as e:
            logger.warning(f"Error parsing URL for third-party check: {url} - {e}")
    return list(set(third_party_urls))


def gather_tech_info(domain: str, subdomains: list) -> list:
    if not isinstance(subdomains, list):
        subdomains = [subdomains]

    domain_root = tldextract.extract(domain).registered_domain

    logger.info(f"Running Nmap once on main domain: {domain}")
    domain_tech_stack = set()
    domain_service_versions = set()

    # Run Nmap only on the main domain
    nmap_output = run_nmap(domain)
    for line in nmap_output.split("\n"):
        if "open" in line:
            tech, full_line = extract_tech_info_from_nmap_line(line)
            if tech:
                logger.info(f"Found tech on {domain}: {tech}")
                domain_tech_stack.add(tech)
                domain_service_versions.add(full_line)

    all_tech_info = []

    for subdomain in subdomains:
        logger.info(f"Starting technology information gathering for: {subdomain}")

        tech_info = {
            "subdomain": subdomain,
            "tech_stack": list(domain_tech_stack),
            "service_version": list(domain_service_versions),
            "email_systems": [],
            "third_party": [],
        }

        # gau URLs
        urls = run_gau(subdomain)
        logger.info(f"Total URLs found by gau for {subdomain}: {len(urls)}")
        js_urls = [u for u in urls if u.endswith(".js")]

        # Detect third-party JavaScript URLs
        tech_info["third_party"] = get_third_party_js(js_urls, domain_root)

        # MX records
        tech_info["email_systems"] = get_mx_records(subdomain)

        logger.info(f"Finished gathering technology info for {subdomain}")
        all_tech_info.append(tech_info)

    return all_tech_info
