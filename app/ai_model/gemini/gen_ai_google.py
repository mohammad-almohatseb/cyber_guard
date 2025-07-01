from __future__ import annotations

import asyncio
import logging
import os
import random
from typing import Any, Dict, List, Union

import google.generativeai as genai
from google.api_core.exceptions import ResourceExhausted

logger = logging.getLogger(__name__)

_API_KEY        = os.getenv("GOOGLE_GENAI_API_KEY", "AIzaSyBNqCVYT5sxDRu_wnLBoUaoB4FIniq0bjg")
_DEFAULT_MODEL  = os.getenv("GEMINI_MODEL", "gemini-2.5-pro")

genai.configure(api_key=_API_KEY)

ContentLike = Union[str, Dict[str, Any], List[Dict[str, Any]], List[str]]

async def generate_content(
    *,
    contents: ContentLike,
    model: str = _DEFAULT_MODEL,
    max_retries: int = 5,
) -> Dict[str, Any]:
    base_delay = 5  # seconds

    for attempt in range(max_retries):
        try:
            gmodel   = genai.GenerativeModel(model)
            response = await gmodel.generate_content_async(contents)

            return {
                "text": response.text,
                "usage": {
                    "input_tokens":  getattr(response.usage_metadata, "prompt_token_count", 0),
                    "output_tokens": getattr(response.usage_metadata, "candidates_token_count", 0),
                    "total_tokens":  getattr(response.usage_metadata, "total_token_count", 0),
                },
            }

        # ── Google quota error ───────────────────────────────────────
        except ResourceExhausted as e:
            if attempt == max_retries - 1:
                raise Exception(
                    f"Gemini rate-limit after {max_retries} attempts: {e}"
                ) from e

            # exponential back-off + jitter
            retry_delay = base_delay * (2 ** attempt) + random.uniform(0, 2)

            # prefer server-suggested delay if present
            api_delay = getattr(getattr(e, "retry_delay", None), "seconds", 0)
            retry_delay = max(retry_delay, api_delay)

            logger.warning(
                "Gemini rate-limit hit → retrying in %.1f s (attempt %s/%s)",
                retry_delay, attempt + 1, max_retries
            )
            await asyncio.sleep(retry_delay)

        except Exception as exc:
            raise Exception(f"Gemini API error: {exc}") from exc


def generate_content_sync(
    *,
    contents: ContentLike,
    model: str = _DEFAULT_MODEL,
) -> Dict[str, Any]:
    gmodel   = genai.GenerativeModel(model)
    response = gmodel.generate_content(contents)

    return {
        "text": response.text,
        "usage": {
            "prompt_tokens":  getattr(response.usage_metadata, "prompt_token_count", 0),
            "completion_tokens": getattr(response.usage_metadata, "candidates_token_count", 0),
            "total_tokens":  getattr(response.usage_metadata, "total_token_count", 0),
        },
    }
