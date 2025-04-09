import dns.resolver
from utils import get_domain_from_url  
from app.api.requests.request_flow import target_url  
from app.config.log_middleware import LoggingMiddleware

dns_results = []

# Logger setup
logger = LoggingMiddleware()

@logger
def fetch_dns_records(domain):
    dns_records = {}

    try:
        # A Records (IPv4)
        a_records = dns.resolver.resolve(domain, 'A')
        dns_records['A'] = [str(record) for record in a_records]

        # AAAA Records (IPv6)
        try:
            aaaa_records = dns.resolver.resolve(domain, 'AAAA')
            dns_records['AAAA'] = [str(record) for record in aaaa_records]
        except dns.resolver.NoAnswer:
            dns_records['AAAA'] = []

        # MX Records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            dns_records['MX'] = [{'preference': record.preference, 'exchange': str(record.exchange)} for record in mx_records]
        except dns.resolver.NoAnswer:
            dns_records['MX'] = []

        # NS Records (Name Servers)
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            dns_records['NS'] = [str(record) for record in ns_records]
        except dns.resolver.NoAnswer:
            dns_records['NS'] = []

        # TXT Records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            dns_records['TXT'] = [str(record) for record in txt_records]
        except dns.resolver.NoAnswer:
            dns_records['TXT'] = []

        # SOA Records
        try:
            soa_records = dns.resolver.resolve(domain, 'SOA')
            dns_records['SOA'] = str(soa_records[0].target)
        except dns.resolver.NoAnswer:
            dns_records['SOA'] = None

    except dns.resolver.NoNameservers:
        logger.error(f"No nameservers found for {domain}")
    except dns.resolver.NXDOMAIN:
        logger.error(f"Domain {domain} does not exist")
    except Exception as e:
        logger.error(f"Error retrieving DNS records for {domain}: {str(e)}")

    return dns_records

def get_dns_information():
    target_domain = get_domain_from_url(target_url)
    
    dns_info = fetch_dns_records(target_domain)
    
    dns_results.append({
        'domain': target_domain,
        'dns_info': dns_info
    })

    logger.info(f"DNS information for {target_domain} retrieved successfully")

    return dns_results  

dns_info = get_dns_information()