from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from app.api.schemas.base_request import RequestType
from app.api.schemas.ip_domain_requests import WebRequest, NetworkRequest 

router = APIRouter()

@router.post("/select_check")   
async def select_check(request: RequestType):
    if request.check_type == "web":
        return JSONResponse(content={"message": "Please provide the domain"})
    elif request.check_type == "network":
        return JSONResponse(content={"message": "Please provide the IP address"})
    raise HTTPException(status_code=400, detail="Invalid check type. Choose 'web' or 'network'")

@router.post("/web_check")
async def web_check(request: WebRequest):
    target_url = request.domain
    return {"message": f"Performing web check on {request.domain}"}

@router.post("/network_check")
async def network_check(request: NetworkRequest):
    target_ip_address = request.ip_address
    return {"message": f"Performing network check on {request.ip_address}"}
