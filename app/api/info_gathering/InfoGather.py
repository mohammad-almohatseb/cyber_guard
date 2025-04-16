import logging
from app.api.info_gathering.web.passive_scan.subdomain_enumeration import run_subdomain_enum
from app.api.info_gathering.web.passive_scan.open_ports import run_open_ports  
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

        subdomains = await run_subdomain_enum(domain)
        if not subdomains:
            logger.warning(f"[InfoGather] No subdomains found for {domain}")
            return {"status": "no_subdomains", "domain": domain}

        open_ports_result = await run_open_ports(domain)  
        if isinstance(open_ports_result, dict) and "error" in open_ports_result:
            logger.error(f"[InfoGather] Error during open port scan: {open_ports_result['error']}")
            open_ports_data = []
        else:
            open_ports_data = open_ports_result

        info_gathering = WebInfoGatheringModel(
            target=domain,
            target_type="web",
            subdomains=[{"subdomain": sub} for sub in subdomains],
            open_ports=open_ports_data,
        )

        await info_gathering.save()
        logger.info(f"[InfoGather] Web info gathering saved for {domain}")

        return {"status": "success", "domain": domain}
