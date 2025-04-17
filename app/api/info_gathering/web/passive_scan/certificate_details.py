from InfoGather import subdomains
import ssl
import socket
import logging
from datetime import datetime


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def check_tls(subdomain, timeout=5):
    try:
        logger.info(f"[TLS Check] Checking TLS for: {subdomain}")

        context = ssl.create_default_context()
        with socket.create_connection((subdomain, 443), timeout=timeout) as conn:
            with context.wrap_socket(conn, server_hostname=subdomain) as ssl_socket:
                cert = ssl_socket.getpeercert()

        
        start_date = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y GMT')
        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')

        
        issuer_name = 'Unknown'
        for item in cert.get('issuer', []):
            for attr_name, attr_value in item:
                if attr_name == 'organizationName':
                    issuer_name = attr_value
                    break

        logger.info(f"[TLS Check] TLS info for {subdomain}: Start={start_date}, Expire={expire_date}, Issuer={issuer_name}")

        return {
            'subdomain': subdomain,
            'has_tls': True,
            'start_date': start_date,
            'expire_date': expire_date,
            'issuer': issuer_name
        }

    except (ssl.SSLError, socket.error, socket.timeout):
        logger.warning(f"[TLS Check] TLS not available for: {subdomain}")
        return {
            'subdomain': subdomain,
            'has_tls': False,
            'start_date': None,
            'expire_date': None,
            'issuer': None
        }


subdomain_list = subdomains


certificate_details = []

for sub in subdomain_list:
    result = check_tls(sub)
    certificate_details.append(result)


for info in certificate_details:
    if info['has_tls']:
        print(f"Subdomain: {info['subdomain']} has TLS.")
        print(f"  ➔ Start Date: {info['start_date']}")
        print(f"  ➔ Expire Date: {info['expire_date']}")
        print(f"  ➔ Issuer: {info['issuer']}\n")
    else:
        print(f"Subdomain: {info['subdomain']} does not have TLS.\n")

