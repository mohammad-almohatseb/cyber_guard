from app.api.info_gathering.web.passive_scan.subdomain_enumeration import run_subdomain_enum
from app.api.info_gathering.web.passive_scan.open_ports import scan_open_ports
from app.api.models.information import WebInfoGatheringModel
from app.api.info_gathering.web.passive_scan.archives_urls import retrieve_archived_urls  
from app.config.log_middleware import LoggingMiddleware

logger = LoggingMiddleware()

class InfoGather:
    def __init__(self):
        pass
    
    async def networkExecution(self):
        pass
        
    async def webExecution(self, domain: str):
        subdomains = await run_subdomain_enum(domain)
        
        open_ports_result = await scan_open_ports(domain)
        
        archive_urls = await retrieve_archived_urls(subdomains)
        
        info_gathering = WebInfoGatheringModel(
            target=domain,
            target_type="web",  
            subdomains=[{"subdomain": sub} for sub in subdomains],  
            open_ports=open_ports_result.get("results", []),  
            archived_urls=archive_urls  
        )

        await info_gathering.save() 
        logger.info(f"Document for {domain} saved to MongoDB.")