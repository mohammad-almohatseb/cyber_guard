from app.api.info_gathering.web.passive_scan.subdomain_enumeration import run_subdomain_enum
from app.api.info_gathering.web.passive_scan.open_ports import scan_open_ports
from app.api.models.information import WebInfoGatheringModel


class InfoGather:
    def __init__(self):
        pass
    
    async def networkExecution(self, ip_address: str):
        pass
        
    async def webExecution(self, domain: str):
        subdomains = await run_subdomain_enum(domain)
        if not subdomains:
            return

        open_ports_result = await scan_open_ports(domain)


        info_gathering = WebInfoGatheringModel(
            target=domain,
            target_type="web",  
            subdomains=[{"subdomain": sub} for sub in subdomains],  
            open_ports=open_ports_result.get("results", []),    
        
        )

        await info_gathering.save() 
