from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from app.api.schemas.base_request import RequestType
from app.api.schemas.ip_domain_requests import WebRequest, NetworkRequest 
from app.api.info_gathering.InfoGather import InfoGather

router = APIRouter()
info_gather = InfoGather()  

@router.post("/select_check")   
async def select_check(request: RequestType):
    check_type = request.check_type.lower().strip()  
    if check_type == "web":
        return JSONResponse(content={"message": "Please provide the domain"})
    elif check_type == "network":
        return JSONResponse(content={"message": "Please provide the IP address"})
    raise HTTPException(status_code=400, detail="Invalid check type. Choose 'web' or 'network'")

@router.post("/web_check")
async def web_check(request: WebRequest):
    target_domain = request.domain.strip()

    if not target_domain:
        raise HTTPException(status_code=400, detail="Domain is required.")

    await info_gather.webExecution(target_domain)

    return JSONResponse(content={
        "message": "Web scan started. Results will be stored in MongoDB.",
        "domain": target_domain
    })

@router.post("/network_check")
async def network_check(request: NetworkRequest):
    target_ip_address = request.ip_address.strip()

    if not target_ip_address:
        raise HTTPException(status_code=400, detail="IP address is required.")

    await info_gather.networkExecution(target_ip_address)

    return JSONResponse(content={
        "message": "Network scan started. Results will be stored in MongoDB.",
        "target_ip_address": target_ip_address
    })
