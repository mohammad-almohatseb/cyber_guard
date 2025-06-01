import logging
from contextvars import ContextVar
from typing import Any, Dict, TypeVar

T = TypeVar('T')
R = TypeVar('R')

request_id_ctx: ContextVar[str] = ContextVar('request_id', default='SYSTEM')
correlation_id_ctx: ContextVar[str] = ContextVar('correlation_id', default='GLOBAL')

# ANSI colors
RESET = "\033[0m"
COLORS = {
    logging.DEBUG: "\033[94m",     # Blue
    logging.INFO: "\033[92m",      # Green
    logging.WARNING: "\033[93m",   # Yellow
    logging.ERROR: "\033[91m",     # Red
    logging.CRITICAL: "\033[95m",  # Magenta
}

# Console handler with color
class ColoredFormatter(logging.Formatter):
    def format(self, record):
        level_color = COLORS.get(record.levelno, "")
        record.msg = f"{level_color}{record.msg}{RESET}"
        return super().format(record)

# Setup logging with separate handlers for console and file
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColoredFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

file_handler = logging.FileHandler('app.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

logging.basicConfig(
    level=logging.DEBUG,
    handlers=[console_handler, file_handler]
)

class ContextLogger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
    
    def _format_message(self, message: str, context: Dict[str, Any] = None) -> str:
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
