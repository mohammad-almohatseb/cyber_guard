import logging

from app.api.info_gathering.web.passive_scan.subdomain_enumeration import run_subdomain_enum
from app.api.info_gathering.web.passive_scan.open_ports import run_open_ports
from app.api.info_gathering.web.passive_scan.archives_urls import enumerate_urls
from app.api.info_gathering.web.passive_scan.certificate_details import enumerate_certificates
from app.api.info_gathering.web.passive_scan.technology_info import gather_tech_info
from app.api.info_gathering.web.passive_scan.directory_enumeration import enum_dir_on_subdomains
from app.api.info_gathering.web.passive_scan.server_info import final_result
from app.api.info_gathering.web.active_scan.input_validation import scan_input_validation
from app.api.info_gathering.web.active_scan.http_headers import scan_https_headers
from app.api.info_gathering.web.active_scan.waf_detection import enumerate_waf

from app.api.info_gathering.network.firewall_detection import enumerate_firewalls
from app.api.info_gathering.network.host_discovery import discover_hosts
from app.api.info_gathering.network.os_detection import scan_os
from app.api.info_gathering.network.service_detection import detect_services

from app.api.models.information import WebInfoGatheringModel, NetworkInfoGathering

logger = logging.getLogger(__name__)


class InfoGather:
    def __init__(self):
        pass

    async def networkExecution(self, ip_address: str):
        ip_address = ip_address.strip()
        logger.info(f"[InfoGather] Starting network scan for {ip_address}")

        # Host discovery
        alive_hosts_result = await discover_hosts(ip_address)
        if not alive_hosts_result:
            logger.warning(f"[InfoGather] No hosts found for {ip_address}")
            return {"status": "no_hosts", "ip_address": ip_address}

        ip_addresses = [host["host"] for host in alive_hosts_result if "host" in host]

        # Firewall detection
        firewall_detection_result = await enumerate_firewalls(ip_addresses)

        # OS detection
        os_detection_result = []
        for ip in ip_addresses:
            result = await scan_os(ip)
            os_detection_result.append(result)

        # Service detection
        service_detection_result = []
        for ip in ip_addresses:
            result = await detect_services(ip)
            service_detection_result.append(result)

        # Save to DB
        info_gathering = NetworkInfoGathering(
            target=ip_address,
            target_type="network",
            alive_hosts=alive_hosts_result,
            firewall_info=firewall_detection_result,
            os_detection=os_detection_result,
            detected_services=service_detection_result
        )
        await info_gathering.save()

        return {"status": "success", "ip_address": ip_address}

    async def webExecution(self, domain: str):
        domain = domain.strip().lower()
        logger.info(f"[InfoGather] Starting web scan for {domain}")

        # Subdomain enumeration
        subdomains_result = await run_subdomain_enum(domain)
        if not subdomains_result:
            logger.warning(f"[InfoGather] No subdomains found for {domain}")
            return {"status": "no_subdomains", "domain": domain}

        subdomains_result.append(domain)

        # Open ports
        open_ports_result = await run_open_ports(domain)
        if isinstance(open_ports_result, dict) and "error" in open_ports_result:
            logger.error(f"[InfoGather] Error during open port scan: {open_ports_result['error']}")
            open_ports_data = []
        else:
            open_ports_data = open_ports_result

        # Archive URLs
        archieve_urls_result = await enumerate_urls([domain])

        # Certificate details
        certificate_details_result = await enumerate_certificates(subdomains_result)

        # Technology info
        technology_info_result = gather_tech_info(domain, subdomains_result)

        # Directory enumeration
        directories_enum_result = await enum_dir_on_subdomains(subdomains_result)

        # Server info
        server_info_result = await final_result(subdomains_result)

        # Input validation
        all_injectables_nested = [item["injectable_urls"] for item in archieve_urls_result if "injectable_urls" in item]
        all_injectables = [url for sublist in all_injectables_nested for url in sublist]
        input_validation_result = await scan_input_validation(all_injectables)

        # HTTPS headers
        https_headers_result = await scan_https_headers(subdomains_result)

        # WAF detection
        waf_detections_result = await enumerate_waf(subdomains_result)

        # Save to DB
        info_gathering = WebInfoGatheringModel(
            target=domain,
            target_type="web",
            subdomains=subdomains_result,
            open_ports=open_ports_data,
            archive_urls=archieve_urls_result,
            certificate_details=certificate_details_result,
            directories=directories_enum_result,
            server_info=server_info_result,
            technology_info=technology_info_result,
            https_headers=https_headers_result,
            input_validation=input_validation_result,
            waf_detections=waf_detections_result
        )
        await info_gathering.save()
        logger.info(f"[InfoGather] Web info gathering saved for {domain}")

        return {"status": "success", "domain": domain}
