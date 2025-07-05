import asyncio
import logging
from typing import Dict, Any

from app.api.info_gathering.web.passive_scan.subdomain_enumeration import run_subdomain_enum
from app.api.info_gathering.web.passive_scan.open_ports import run_open_ports
from app.api.info_gathering.web.passive_scan.archives_urls import enumerate_urls
from app.api.info_gathering.web.passive_scan.certificate_details import enumerate_certificates
from app.api.info_gathering.web.passive_scan.directory_enumeration import enum_dir_on_subdomains
from app.api.info_gathering.web.passive_scan.server_info import final_result
from app.api.info_gathering.web.active_scan.http_headers import scan_https_headers
from app.api.info_gathering.web.active_scan.waf_detection import enumerate_waf

from app.api.info_gathering.network.firewall_detection import enumerate_firewalls
from app.api.info_gathering.network.host_discovery import discover_hosts
from app.api.info_gathering.network.os_detection import scan_os
from app.api.info_gathering.network.service_detection import scan_open_services

from app.api.models.information import WebInfoGatheringModel, NetworkInfoGathering

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class InfoGather:
    def __init__(self):
        pass

    async def webExecution(self, domain: str) -> Dict[str, Any]:
        domain = domain.strip().lower()
        logger.info(f"[WebScan] Starting scan for domain: {domain}")

        try:
            subdomains_result = await run_subdomain_enum(domain)
            logger.debug(f"[WebScan] Subdomains found: {subdomains_result}")
        except Exception as e:
            logger.exception(f"[WebScan] Error enumerating subdomains: {e}")
            return {"status": "subdomain_error", "domain": domain}

        if not subdomains_result:
            logger.warning(f"[WebScan] No subdomains found for {domain}")
            return {"status": "no_subdomains", "domain": domain}

        subdomains_result.append(domain)

        try:
            open_ports_data, archive_urls, cert_details, directories, server_info, https_headers, waf_detections = await asyncio.gather(
                run_open_ports(domain),
                enumerate_urls([domain]),
                enumerate_certificates(subdomains_result),
                enum_dir_on_subdomains(subdomains_result),
                final_result(subdomains_result),
                scan_https_headers(subdomains_result),
                enumerate_waf(subdomains_result)
            )
        except Exception as e:
            logger.exception(f"[WebScan] Error during scan tasks: {e}")
            return {"status": "scan_error", "domain": domain}

        try:
            web_info = WebInfoGatheringModel(
                target=domain,
                target_type="web",
                subdomains=subdomains_result,
                open_ports=open_ports_data,
                archive_urls=archive_urls,
                certificate_details=cert_details,
                directories=directories,
                server_info=server_info,
                https_headers=https_headers,
                waf_detections=waf_detections,
            )
            await web_info.save()
            logger.info(f"[WebScan] Web scan completed and saved for domain: {domain}")
            return {"status": "success", "domain": domain}
        except Exception as e:
            logger.exception(f"[WebScan] Failed to save results: {e}")
            return {"status": "db_error", "domain": domain}

    async def networkExecution(self, ip_address: str) -> Dict[str, Any]:
        ip_address = ip_address.strip()
        logger.info(f"[NetScan] Starting network scan for {ip_address}")

        try:
            alive_hosts_result = await discover_hosts(ip_address)
        except Exception as e:
            logger.exception(f"[NetScan] Error discovering hosts: {e}")
            return {"status": "discover_error", "ip_address": ip_address}

        if not alive_hosts_result:
            logger.warning(f"[NetScan] No hosts found for {ip_address}")
            return {"status": "no_hosts", "ip_address": ip_address}

        ip_addresses = [host["host"] for host in alive_hosts_result if "host" in host]

        try:
            firewall_detection_result = await enumerate_firewalls(ip_addresses)
            os_detection_result = await asyncio.gather(*[scan_os(ip) for ip in ip_addresses])
            service_detection_result = await asyncio.gather(*[scan_open_services(ip) for ip in ip_addresses])
        except Exception as e:
            logger.exception(f"[NetScan] Error during scan tasks: {e}")
            return {"status": "scan_error", "ip_address": ip_address}

        try:
            network_info = NetworkInfoGathering(
                target=ip_address,
                target_type="network",
                alive_hosts=alive_hosts_result,
                firewall_info=firewall_detection_result,
                os_detection=os_detection_result,
                detected_services=service_detection_result
            )
            await network_info.save()
            logger.info(f"[NetScan] Network info saved for {ip_address}")
            return {"status": "success", "ip_address": ip_address}
        except Exception as e:
            logger.exception(f"[NetScan] Failed to save network results: {e}")
            return {"status": "db_error", "ip_address": ip_address}
