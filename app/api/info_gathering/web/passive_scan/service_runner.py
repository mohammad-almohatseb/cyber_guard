from app.config.log_decorator import log_app
from subdomain_enumeration import run_subdomain_enum
from app.api.requests.request_flow import target_url
from open_ports import scan_open_ports
from archives_urls import retrieve_archived_urls
from utils import get_domain_from_url

@log_app("service_runner")
def run_service_runner(target_url):
    # Parse the target domain from the given URL
    parsed_domain = get_domain_from_url(target_url)


    # Run subdomain enumeration
    subdomains = run_subdomain_enum(parsed_domain)

    # Run open port scanning
    open_ports_result = scan_open_ports(parsed_domain)
    open_ports = open_ports_result.get("results", [])


    # Retrieve archived URLs for each subdomain
    print("Starting archived URL retrieval...")
    for subdomain in subdomains:
        archived_urls = retrieve_archived_urls(subdomain)

    

# Entry point to execute the service runner
if __name__ == "__main__":
    run_service_runner(target_url)
