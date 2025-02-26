from pydantic import BaseModel, HttpUrl, IPv4Address

class WebRequest (BaseModel):
    domain : HttpUrl

class NetworkRequest (BaseModel):
    ip_address : list[IPv4Address]
    