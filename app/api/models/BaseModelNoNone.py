from pydantic import BaseModel


class BaseModelNoNone(BaseModel):
    def dict(self, *args,exclude_none:bool=True, **kwargs):
        return super().model_dump(*args, exclude_none=exclude_none, **kwargs)
    
    def json(self, *args, exclude_none:bool=True, **kwargs):
        return super().model_dump(*args, exclude_none=exclude_none, **kwargs)
    
    class Config:
        arbitrary_types_allowed = True