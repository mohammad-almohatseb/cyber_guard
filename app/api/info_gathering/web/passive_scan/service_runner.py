from subdomain_enumeration import run_subdomain_enum
from app.api.requests.request_flow import target_url
from open_ports import scan_open_ports
from utils import get_domain_from_url

def run_service_runner(target_url):
    parsed_domain = get_domain_from_url(target_url)
    subdomains = run_subdomain_enum(parsed_domain)
    
    print("Subdomain enumeration completed.")
    print(f"Collected subdomains: {subdomains}")
    print("number of subdomains found:", len(subdomains))

    open_ports_result = scan_open_ports(parsed_domain)
    open_ports = open_ports_result.get("results", [])
    
    print("Open port scan completed.")
    print(f"Open ports found: {open_ports}")
    print("Number of open ports:", len(open_ports))
    

if __name__ == "__main__":
    parsed_domain = get_domain_from_url(target_url)
    run_service_runner(parsed_domain)
