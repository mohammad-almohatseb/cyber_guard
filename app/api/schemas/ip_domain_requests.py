from pydantic import BaseModel, HttpUrl, IPvAnyAddress

class WebRequest (BaseModel):
    domain : HttpUrl

class NetworkRequest (BaseModel):
    ip_address : list[IPvAnyAddress]
    