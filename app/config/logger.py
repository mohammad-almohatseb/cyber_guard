import logging
from contextvars import ContextVar
from typing import Any, Dict, TypeVar

T = TypeVar('T')
R = TypeVar('R')

request_id_ctx: ContextVar[str] = ContextVar('request_id', default='SYSTEM')
correlation_id_ctx: ContextVar[str] = ContextVar('correlation_id', default='GLOBAL')

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)

class ContextLogger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
    
    def _format_message(self, message: str, context: Dict[str, Any] = None) -> str:
        """Enhance message with context and request IDs"""
        context = context or {}
        ctx_str = ' '.join([f"{k}={v}" for k, v in context.items()])
        return f"[{request_id_ctx.get()}] [{correlation_id_ctx.get()}] {message} | {ctx_str}"

    def debug(self, message: str, context: Dict[str, Any] = None):
        self.log(logging.DEBUG, message, context)
        
    def info(self, message: str, context: Dict[str, Any] = None):
        self.log(logging.INFO, message, context)
        
    def warning(self, message: str, context: Dict[str, Any] = None):
        self.log(logging.WARNING, message, context)
        
    def error(self, message: str, context: Dict[str, Any] = None):
        self.log(logging.ERROR, message, context)
        
    def critical(self, message: str, context: Dict[str, Any] = None):
        self.log(logging.CRITICAL, message, context)

    def log(self, level: int, message: str, context: Dict[str, Any] = None):
        formatted_message = self._format_message(message, context)
        self.logger.log(level, formatted_message)

def get_logger(name: str) -> ContextLogger:
    return ContextLogger(name)
