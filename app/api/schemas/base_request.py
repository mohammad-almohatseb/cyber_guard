from pydantic import BaseModel, Field

class RequestType(BaseModel):
    """RequestType Model"""
    check_type: str = Field(..., pattern="^(web|network)$", description="Type of check: 'web' or 'network'")