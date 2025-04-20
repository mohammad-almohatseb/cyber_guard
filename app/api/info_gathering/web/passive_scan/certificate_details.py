import ssl
import socket
import logging
from datetime import datetime
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def fetch_tls_certificate(subdomain: str, timeout: int = 5) -> dict:
    try:
        logger.info(f"[TLS Check] Checking TLS for: {subdomain}")

        context = ssl.create_default_context()
        with socket.create_connection((subdomain, 443), timeout=timeout) as conn:
            with context.wrap_socket(conn, server_hostname=subdomain) as ssl_socket:
                cert = ssl_socket.getpeercert()

        start_date = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y GMT')
        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')

        issuer_name = next(
            (attr_value for item in cert.get('issuer', [])
             for attr_name, attr_value in item if attr_name == 'organizationName'),
            'Unknown'
        )

        return {
            'subdomain': subdomain,
            'has_tls': True,
            'start_date': start_date,
            'expire_date': expire_date,
            'issuer': issuer_name
        }

    except (ssl.SSLError, socket.error, socket.timeout):
        logger.warning(f"[TLS Check] TLS not available for: {subdomain}")
    except Exception as e:
        logger.error(f"[TLS Check] Unexpected error for {subdomain}: {e}")

    return {
        'subdomain': subdomain,
        'has_tls': False,
        'start_date': None,
        'expire_date': None,
        'issuer': None
    }


async def enumerate_certificates(subdomains: list[str]) -> list[dict]:
    certificate_details = []

    tasks = [asyncio.to_thread(fetch_tls_certificate, sub) for sub in subdomains]
    results = await asyncio.gather(*tasks)

    for info in results:
        certificate_details.append(info)
        if info['has_tls']:
            logger.info(f" Subdomain: {info['subdomain']} has TLS.")
            logger.info(f"   ➔ Start Date: {info['start_date']}")
            logger.info(f"   ➔ Expire Date: {info['expire_date']}")
            logger.info(f"   ➔ Issuer: {info['issuer']}\n")
        else:
            logger.info(f" Subdomain: {info['subdomain']} does not have TLS.\n")

    return certificate_details
