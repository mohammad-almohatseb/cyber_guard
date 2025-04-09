from pydantic import BaseModel, IPvAnyAddress, constr

class WebRequest(BaseModel):
    domain: str

class NetworkRequest(BaseModel):
    ip_address: list[IPvAnyAddress]
