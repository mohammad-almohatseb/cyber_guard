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
logger.setLevel(logging.DEBUG)  


class InfoGather:
    def __init__(self):
        pass

    async def networkExecution(self, ip_address: str):
        ip_address = ip_address.strip()
        logger.info(f"[InfoGather] Starting network scan for {ip_address}")

        alive_hosts_result = await discover_hosts(ip_address)
        logger.debug(f"[InfoGather] Discovered hosts: {alive_hosts_result}")
        if not alive_hosts_result:
            logger.warning(f"[InfoGather] No hosts found for {ip_address}")
            return {"status": "no_hosts", "ip_address": ip_address}

        ip_addresses = [host["host"] for host in alive_hosts_result if "host" in host]

        firewall_detection_result = await enumerate_firewalls(ip_addresses)
        logger.debug(f"[InfoGather] Firewall detection result: {firewall_detection_result}")

        os_detection_result = []
        for ip in ip_addresses:
            result = await scan_os(ip)
            logger.debug(f"[InfoGather] OS detection result for {ip}: {result}")
            os_detection_result.append(result)

        service_detection_result = []
        for ip in ip_addresses:
            result = await detect_services(ip)
            logger.debug(f"[InfoGather] Service detection result for {ip}: {result}")
            service_detection_result.append(result)

        network_info_gathering = NetworkInfoGathering(
            target=ip_address,
            target_type="network",
            alive_hosts=alive_hosts_result,
            firewall_info=firewall_detection_result,
            os_detection=os_detection_result,
            detected_services=service_detection_result
        )
        await network_info_gathering.save()
        logger.info(f"[InfoGather] Network info gathering saved for {ip_address}")

        return {"status": "success", "ip_address": ip_address}

    async def webExecution(self, domain: str):
        domain = domain.strip().lower()
        logger.info(f"[InfoGather] Starting web scan for {domain}")

        subdomains_result = await run_subdomain_enum(domain)
        logger.debug(f"[InfoGather] Subdomains found: {subdomains_result}")
        if not subdomains_result:
            logger.warning(f"[InfoGather] No subdomains found for {domain}")
            return {"status": "no_subdomains", "domain": domain}
        subdomains_result.append(domain)

        open_ports_result = await run_open_ports(domain)
        logger.debug(f"[InfoGather] Open ports scan result: {open_ports_result}")
        if isinstance(open_ports_result, dict) and "error" in open_ports_result:
            logger.error(f"[InfoGather] Error during open port scan: {open_ports_result['error']}")
            open_ports_data = []
        else:
            open_ports_data = open_ports_result

        archieve_urls_result = await enumerate_urls([domain])
        logger.debug(f"[InfoGather] Archive URLs result: {archieve_urls_result}")

        certificate_details_result = await enumerate_certificates(subdomains_result)
        logger.debug(f"[InfoGather] Certificate details: {certificate_details_result}")

        technology_info_result = gather_tech_info(domain, subdomains_result)
        logger.debug(f"[InfoGather] Technology info: {technology_info_result}")

        directories_enum_result = await enum_dir_on_subdomains(subdomains_result)
        logger.debug(f"[InfoGather] Directory enumeration: {directories_enum_result}")

        server_info_result = await final_result(subdomains_result)
        logger.debug(f"[InfoGather] Server info result: {server_info_result}")

        all_injectables_nested = [item["injectable_urls"] for item in archieve_urls_result if "injectable_urls" in item]
        all_injectables = [url for sublist in all_injectables_nested for url in sublist]
        logger.debug(f"[InfoGather] URLs for input validation: {all_injectables}")
        input_validation_result = await scan_input_validation(all_injectables)
        logger.debug(f"[InfoGather] Input validation result: {input_validation_result}")

        https_headers_result = await scan_https_headers(subdomains_result)
        logger.debug(f"[InfoGather] HTTPS headers result: {https_headers_result}")

        waf_detections_result = await enumerate_waf(subdomains_result)
        logger.debug(f"[InfoGather] WAF detection result: {waf_detections_result}")

        web_info_gathering = WebInfoGatheringModel(
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
        await web_info_gathering.save()
        logger.info(f"[InfoGather] Web info gathering saved for {domain}")

        return {"status": "success", "domain": domain}
