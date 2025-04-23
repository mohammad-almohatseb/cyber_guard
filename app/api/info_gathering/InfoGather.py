import logging
from app.api.info_gathering.web.passive_scan.subdomain_enumeration import run_subdomain_enum
from app.api.info_gathering.web.passive_scan.open_ports import run_open_ports  
from app.api.info_gathering.web.passive_scan.archives_urls import enumerate_urls
from app.api.info_gathering.web.passive_scan.certificate_details import enumerate_certificates
from app.api.models.information import WebInfoGatheringModel

logger = logging.getLogger(__name__)

class InfoGather:
    def __init__(self):
        pass

    async def networkExecution(self, ip_address: str):
        pass

    async def webExecution(self, domain: str):
        domain = domain.strip().lower()
        logger.info(f"[InfoGather] Starting web scan for {domain}")

# subdomain enumeration
        subdomains_result = await run_subdomain_enum(domain)
        if not subdomains_result:
            logger.warning(f"[InfoGather] No subdomains found for {domain}")
            return {"status": "no_subdomains", "domain": domain}

        subdomains_result.append(domain)

# open ports
        open_ports_result = await run_open_ports(domain)  
        if isinstance(open_ports_result, dict) and "error" in open_ports_result:
             logger.error(f"[InfoGather] Error during open port scan: {open_ports_result['error']}")
             open_ports_data = []
        else:
             open_ports_data = open_ports_result   
            
#archive urls        
        archieve_urls_result = await enumerate_urls([domain])




#certificate details

        certificate_details_result= await enumerate_certificates(subdomains_result)


        
        info_gathering = WebInfoGatheringModel(
            target=domain,
            target_type="web",
            subdomains=subdomains_result,
            open_ports=open_ports_result,
            archive_urls=archieve_urls_result,
            certificate_details=certificate_details_result,
        )

        await info_gathering.save()
        logger.info(f"[InfoGather] Web info gathering saved for {domain}")

        return {"status": "success", "domain": domain}
