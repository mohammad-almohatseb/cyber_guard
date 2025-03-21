import time
import inspect

from functools import wraps
from typing import Callable, TypeVar, cast

from app.config.logger import get_logger


T = TypeVar('T')
R = TypeVar('R')


def log_app(component: str):
    def decorator(func: Callable[..., R]) -> Callable[..., R]:
        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> R:
            logger = get_logger(component)
            start_time = time.time()
            func_args = inspect.signature(func).bind(*args, **kwargs).arguments
            sanitized_args = _sanitize_arguments(func_args)

            try:
                logger.debug("ENTRY", {
                    "action": func.__name__,
                    "arguments": sanitized_args,
                    "type": "START"
                })

                result = await func(*args, **kwargs)
                duration = time.time() - start_time

                logger.debug("EXIT", {
                    "action": func.__name__,
                    "duration": f"{duration:.3f}s",
                    "type": "END"
                })
                return result

            except Exception as e:
                duration = time.time() - start_time
                logger.error("ERROR", {
                    "action": func.__name__,
                    "error": str(e),
                    "type": "ERROR",
                    "duration": f"{duration:.3f}s",
                    "exception": type(e).__name__
                })
                raise

        @wraps(func)
        def sync_wrapper(*args, **kwargs) -> R:
            logger = get_logger(component)
            start_time = time.time()
            func_args = inspect.signature(func).bind(*args, **kwargs).arguments
            sanitized_args = _sanitize_arguments(func_args)

            try:
                logger.info("ENTRY", {
                    "action": func.__name__,
                    "arguments": sanitized_args,
                    "type": "START"
                })

                result = func(*args, **kwargs)
                duration = time.time() - start_time

                logger.info("EXIT", {
                    "action": func.__name__,
                    "duration": f"{duration:.3f}s",
                    "type": "END"
                })
                return result

            except Exception as e:
                duration = time.time() - start_time
                logger.error("ERROR", {
                    "action": func.__name__,
                    "error": str(e),
                    "type": "ERROR",
                    "duration": f"{duration:.3f}s",
                    "exception": type(e).__name__
                })
                raise

        if inspect.iscoroutinefunction(func):
            return cast(Callable[..., R], async_wrapper)
        else:
            return cast(Callable[..., R], sync_wrapper)
            
    return decorator

def log_class_methods(component: str):
    def decorator(cls):
        for attr_name, attr in cls.__dict__.items():
            if inspect.isfunction(attr):
                decorated = log_app(component)(attr)
                setattr(cls, attr_name, decorated)
        return cls
    return decorator


def _sanitize_arguments(args: dict) -> dict:
    sanitized = {}
    sensitive_keys = {'password', 'token', 'secret', 'key', 'auth', 'credential'}
    
    for k, v in args.items():
        if any(sens in k.lower() for sens in sensitive_keys):
            sanitized[k] = '*****'
        elif k == 'self' or k == 'cls':
            continue
        else:
            str_v = str(v)
            if len(str_v) > 500:
                sanitized[k] = f"{str_v[:500]}... [truncated]"
            else:
                sanitized[k] = v
                
    return sanitized