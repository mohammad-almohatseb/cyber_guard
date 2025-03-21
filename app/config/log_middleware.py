from contextvars import ContextVar
import time
import uuid
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.config.logger import get_logger


request_id_ctx: ContextVar[str] = ContextVar('request_id', default='SYSTEM')
correlation_id_ctx: ContextVar[str] = ContextVar('correlation_id', default='GLOBAL')

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        correlation_id = request.headers.get('X-Correlation-ID', request_id)
        
        # Set context variables
        request_id_token = request_id_ctx.set(request_id)
        correlation_id_token = correlation_id_ctx.set(correlation_id)
        
        logger = get_logger("HTTP")
        start_time = time.time()

        try:
            # Log request start
            logger.info("REQUEST_START", {
                "method": request.method,
                "path": request.url.path,
                "query": dict(request.query_params),
                "client": request.client.host if request.client else "unknown"
            })

            response = await call_next(request)

            # Log request completion
            duration = time.time() - start_time
            logger.info("REQUEST_END", {
                "status": response.status_code,
                "duration": f"{duration:.3f}s",
                "content_length": response.headers.get('Content-Length', 'unknown')
            })

            return response

        except Exception as e:
            duration = time.time() - start_time
            logger.error("REQUEST_FAILED", {
                "error": str(e),
                "duration": f"{duration:.3f}s",
                "exception": type(e).__name__
            })
            raise
        finally:
            # Reset context vars
            request_id_ctx.reset(request_id_token)
            correlation_id_ctx.reset(correlation_id_token)