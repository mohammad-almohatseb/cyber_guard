from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException, status, Body, Query
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

from app.ai_model.web.web_build_prompt import build_web_prompt
from app.ai_model.network.network_build_prompt import build_network_prompt
from app.ai_model.gemini.gen_ai_google import generate_content

from app.api.models.ai_collection import AI_RISK_REPORT
from app.api.schemas.base_request import RequestType
from app.api.schemas.ip_domain_requests import WebRequest, NetworkRequest
from app.api.info_gathering.InfoGather import InfoGather
from app.api.vulnerability_assesment.VulnerabilityAssessment import VulnerabilityAssessment
from app.api.exploiting.Exploiting import Exploiting

MODEL_API_URL = os.getenv("MODEL_API_URL", "http://host.docker.internal:8080/chat")
MONGO_URI = os.getenv(
    "MONGO_URI", "mongodb://admin:password@mongodb:27017/cyberguard?authSource=admin"
)

logger = logging.getLogger(__name__)

mongo = AsyncIOMotorClient(MONGO_URI).get_default_database()
router = APIRouter(prefix="/api")

info_gather = InfoGather()
vulnerability_assessment = VulnerabilityAssessment()
exploiting = Exploiting()

class AIRiskRequest(BaseModel):
    domain: str

class NetworkAIRiskRequest(BaseModel):
    ip_address: str

class GeminiWebRequest(BaseModel):
    domain: str = Field(..., example="vulnweb.com")
    executive_summary_words: int | None = None
    include_raw_block: bool | None = None
    extra_sections: List[str] | None = None

class GeminiNetworkRequest(BaseModel):
    ip_address: str = Field(..., example="192.168.1.1")
    executive_summary_words: int | None = None
    include_raw_block: bool | None = None
    extra_sections: List[str] | None = None

class GeminiWebResponse(BaseModel):
    domain: str
    meta: Dict[str, Any]
    report_md: str
    llm_raw: Dict[str, Any] | None = None

class GeminiNetworkResponse(BaseModel):
    ip_address: str
    meta: Dict[str, Any]
    report_md: str
    llm_raw: Dict[str, Any] | None = None

def _extract_json(text: str) -> Dict[str, Any]:
    clean = text.replace("JSON:", "").split("JSON_END", 1)[0].split("```", 1)[-1].strip()
    start = clean.find("{")
    if start == -1:
        raise json.JSONDecodeError("No JSON object", clean, 0)

    buf, depth, in_str, esc = "", 0, False, False
    for ch in clean[start:]:
        buf += ch
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break

    if depth > 0:
        buf += "}" * depth

    try:
        return json.loads(buf)
    except json.JSONDecodeError:
        last = buf.rfind(",")
        if last != -1:
            return json.loads(buf[:last] + "}")
        raise

async def _call_llm(prompt: str) -> Dict[str, Any]:
    payload = {
        "prompt": prompt,
        "max_tokens": 700,
        "temperature": 0.6,
        "top_p": 0.9,
        "do_sample": False,
    }
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(MODEL_API_URL, json=payload)
        resp.raise_for_status()
    return _extract_json(resp.text)

AI_RISK_REPORT = mongo["ai_risk_reports"]

def _store_report(report_type: str, target: str, prompt: str, result: Dict[str, Any]):
    AI_RISK_REPORT.insert_one({
        "report_type": report_type,
        "target": target,
        "prompt": prompt,
        "result": result,
        "created_at": datetime.now(timezone.utc),
    })

@router.post("/select_check")
async def select_check(request: RequestType):
    t = request.check_type.lower().strip()
    if t == "web":
        return JSONResponse({"message": "Please provide the domain"})
    if t == "network":
        return JSONResponse({"message": "Please provide the IP address"})
    raise HTTPException(400, "Invalid check type. Choose 'web' or 'network'")

@router.post("/web_check")
async def web_check(request: WebRequest):
    domain = request.domain.strip()
    if not domain:
        raise HTTPException(400, "Domain is required.")
    await info_gather.webExecution(domain)
    return JSONResponse({"message": "Web scan started.", "domain": domain})

@router.post("/network_check")
async def network_check(request: NetworkRequest):
    ip = request.ip_address.strip()
    if not ip:
        raise HTTPException(400, "IP address is required.")
    await info_gather.networkExecution(ip)
    return JSONResponse({"message": "Network scan started.", "ip": ip})

@router.post("/web_vulnerability_assessment")
async def web_vulnerability_assessment(request: WebRequest):
    await vulnerability_assessment.web_vulnerability_assesment(domain=request.domain)
    return JSONResponse({"message": "Vulnerability assessment started."})

@router.post("/network_vulnerability_assessment")
async def network_vulnerability_assessment(request: NetworkRequest):
    await vulnerability_assessment.network_vulnerability_assesment(ip_address=request.ip_address)
    return JSONResponse({"message": "Vulnerability assessment started."})

@router.post("/web_exploiting")
async def web_vulnerability_exploiting(request: WebRequest):
    await exploiting.web_vulnerability_exploiting(domain=request.domain)
    return JSONResponse({"message": "Exploitation started."})

@router.post("/network_exploiting")
async def network_vulnerability_exploiting(request: NetworkRequest):
    await exploiting.network_vulnerability_exploiting(ip_address=request.ip_address)
    return JSONResponse({"message": "Exploitation started."})

@router.post("/web_ai_risk_report", response_class=JSONResponse)
async def web_ai_risk_report(req: AIRiskRequest):
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(400, "Domain cannot be empty")
    logger.info("Processing risk report for domain: %s", domain)
    try:
        prompt = await build_web_prompt(domain)
        result = await _call_llm(prompt)
        _store_report("web", domain, prompt, result)
        return JSONResponse({"output": result})
    except Exception as e:
        logger.error("Risk report failed: %s", e)
        raise HTTPException(502, f"Risk report error: {e}")

@router.post("/network_ai_risk_report", response_class=JSONResponse)
async def network_ai_risk_report(req: NetworkAIRiskRequest):
    ip = req.ip_address.strip()
    if not ip:
        raise HTTPException(400, "IP address cannot be empty")
    logger.info("Processing risk report for network: %s", ip)
    try:
        prompt = await build_network_prompt(ip)
        result = await _call_llm(prompt)
        _store_report("network", ip, prompt, result)
        return JSONResponse({"output": result})
    except Exception as e:
        logger.error("Risk report failed: %s", e)
        raise HTTPException(502, f"Risk report error: {e}")

@router.post("/web_gemini", status_code=status.HTTP_200_OK)
async def web_gemini(
    req: GeminiWebRequest | None = Body(None),
    domain: str | None = Query(None, alias="content", description="Domain if no body sent"),
):
    """Generate a web application penetration test report using Gemini AI"""
    logger.info("=== WEB GEMINI ENDPOINT CALLED ===")
    
    try:
        # Handle request parameters
        if req is None:
            if domain is None:
                logger.error("No domain provided in request")
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Domain required")
            req = GeminiWebRequest(domain=domain)

        logger.info(f"Processing Gemini web report for domain: {req.domain}")

        # Test 1: Check if imports work
        try:
            logger.info("Testing imports...")
            from app.ai_model.gemini.get_webdata import get_webtarget_data, build_gemini_web_prompt, PromptConfig
            logger.info("✓ Imports successful")
        except ImportError as e:
            logger.error(f"✗ Import failed: {e}")
            raise HTTPException(500, f"Import error: {e}")

        # Test 2: Get web target data
        try:
            logger.info(f"Getting web target data for: {req.domain}")
            data = await get_webtarget_data(req.domain)
            logger.info(f"✓ Web target data retrieved: {list(data.keys())}")
            operational = data["operational"]
            logger.info(f"✓ Operational data keys: {list(operational.keys())}")
        except Exception as e:
            logger.error(f"✗ Failed to get web target data: {e}")
            raise HTTPException(500, f"Data retrieval error: {e}")
        
        # Test 3: Configure prompt settings
        try:
            cfg = PromptConfig(
                executive_summary_words=req.executive_summary_words or 200,
                include_raw_block=req.include_raw_block if req.include_raw_block is not None else False,
                extra_sections=req.extra_sections or [],
            )
            logger.info("✓ PromptConfig created")
        except Exception as e:
            logger.error(f"✗ PromptConfig failed: {e}")
            raise HTTPException(500, f"Config error: {e}")
        
        # Test 4: Build the prompt
        try:
            prompt = build_gemini_web_prompt(operational, cfg=cfg)
            logger.info(f"✓ Prompt built, length: {len(prompt)} characters")
            logger.debug(f"Prompt preview: {prompt[:200]}...")
        except Exception as e:
            logger.error(f"✗ Prompt building failed: {e}")
            raise HTTPException(500, f"Prompt error: {e}")

        # Test 5: Generate content using Gemini
        try:
            logger.info("Calling Gemini API...")
            model_name = "gemini-2.5-pro"
            
            # Check if generate_content function exists
            if not hasattr(generate_content, '__call__'):
                raise HTTPException(500, "generate_content is not callable")
                
            llm_resp = await generate_content(model=model_name, contents=prompt)
            logger.info(f"✓ Gemini response received: {type(llm_resp)}")
            logger.info(f"Response keys: {list(llm_resp.keys()) if isinstance(llm_resp, dict) else 'Not a dict'}")
        except Exception as e:
            logger.error(f"✗ Gemini API call failed: {e}")
            raise HTTPException(500, f"Gemini error: {e}")
        
        # Test 6: Extract the report content
        report_md = llm_resp.get("text") or llm_resp.get("content") or ""
        
        if not report_md:
            logger.warning("Empty response from Gemini model")
            logger.info(f"Full LLM response: {llm_resp}")
            report_md = "# Error: Empty response from AI model"
        else:
            logger.info(f"✓ Report generated, length: {len(report_md)} chars")

        # Test 7: Build response
        response_data = {
            "domain": req.domain,
            "meta": data.get("meta", {}),
            "report_md": report_md,
            "llm_raw": llm_resp,
        }
        
        logger.info("✓ Response data built successfully")
        logger.info("=== WEB GEMINI ENDPOINT COMPLETED ===")
        
        return JSONResponse(status_code=status.HTTP_200_OK, content=response_data)
        
    except HTTPException:
        logger.error("HTTPException raised, re-raising")
        raise
    except Exception as exc:
        logger.exception(f"Unexpected error in Web Gemini endpoint: {exc}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, 
            detail=f"Gemini model error: {str(exc)}"
        ) from exc

@router.post("/network_gemini", status_code=status.HTTP_200_OK)
async def network_gemini(
    req: GeminiNetworkRequest | None = Body(None),
    ip_address: str | None = Query(None, alias="content", description="IP address if no body sent"),
):
    """Generate a network penetration test report using Gemini AI"""
    logger.info("=== NETWORK GEMINI ENDPOINT CALLED ===")
    
    try:
        # Handle request parameters
        if req is None:
            if ip_address is None:
                logger.error("No IP address provided in request")
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "IP address required")
            req = GeminiNetworkRequest(ip_address=ip_address)

        logger.info(f"Processing Gemini network report for IP: {req.ip_address}")

        # Test 1: Check if imports work
        try:
            logger.info("Testing imports...")
            from app.ai_model.gemini.get_networkdata import get_networktarget_data, build_gemini_network_prompt, PromptConfig
            logger.info("✓ Imports successful")
        except ImportError as e:
            logger.error(f"✗ Import failed: {e}")
            raise HTTPException(500, f"Import error: {e}")

        # Test 2: Get network target data
        try:
            logger.info(f"Getting network target data for: {req.ip_address}")
            data = await get_networktarget_data(req.ip_address)
            logger.info(f"✓ Network target data retrieved: {list(data.keys())}")
            operational = data["operational"]
            logger.info(f"✓ Operational data keys: {list(operational.keys())}")
        except Exception as e:
            logger.error(f"✗ Failed to get network target data: {e}")
            raise HTTPException(500, f"Data retrieval error: {e}")
        
        # Test 3: Configure prompt settings
        try:
            cfg = PromptConfig(
                executive_summary_words=req.executive_summary_words or 200,
                include_raw_block=req.include_raw_block if req.include_raw_block is not None else False,
                extra_sections=req.extra_sections or [],
            )
            logger.info("✓ PromptConfig created")
        except Exception as e:
            logger.error(f"✗ PromptConfig failed: {e}")
            raise HTTPException(500, f"Config error: {e}")
        
        # Test 4: Build the prompt
        try:
            prompt = build_gemini_network_prompt(operational, cfg=cfg)
            logger.info(f"✓ Prompt built, length: {len(prompt)} characters")
            logger.debug(f"Prompt preview: {prompt[:200]}...")
        except Exception as e:
            logger.error(f"✗ Prompt building failed: {e}")
            raise HTTPException(500, f"Prompt error: {e}")

        # Test 5: Generate content using Gemini
        try:
            logger.info("Calling Gemini API...")
            model_name = "gemini-2.5-pro"
            
            # Check if generate_content function exists
            if not hasattr(generate_content, '__call__'):
                raise HTTPException(500, "generate_content is not callable")
                
            llm_resp = await generate_content(model=model_name, contents=prompt)
            logger.info(f"✓ Gemini response received: {type(llm_resp)}")
            logger.info(f"Response keys: {list(llm_resp.keys()) if isinstance(llm_resp, dict) else 'Not a dict'}")
        except Exception as e:
            logger.error(f"✗ Gemini API call failed: {e}")
            raise HTTPException(500, f"Gemini error: {e}")
        
        # Test 6: Extract the report content
        report_md = llm_resp.get("text") or llm_resp.get("content") or ""
        
        if not report_md:
            logger.warning("Empty response from Gemini model")
            logger.info(f"Full LLM response: {llm_resp}")
            report_md = "# Error: Empty response from AI model"
        else:
            logger.info(f"✓ Report generated, length: {len(report_md)} chars")

        # Test 7: Build response
        response_data = {
            "ip_address": req.ip_address,
            "meta": data.get("meta", {}),
            "report_md": report_md,
            "llm_raw": llm_resp,
        }
        
        logger.info("✓ Response data built successfully")
        logger.info("=== NETWORK GEMINI ENDPOINT COMPLETED ===")
        
        return JSONResponse(status_code=status.HTTP_200_OK, content=response_data)
        
    except HTTPException:
        logger.error("HTTPException raised, re-raising")
        raise
    except Exception as exc:
        logger.exception(f"Unexpected error in Network Gemini endpoint: {exc}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, 
            detail=f"Gemini model error: {str(exc)}"
        ) from exc