from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx
from fastapi import APIRouter, HTTPException, status, Body, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.ai_model.web.web_build_prompt import build_web_prompt
from app.ai_model.network.network_build_prompt import build_network_prompt
from app.ai_model.gemini.gen_ai_google import generate_content

from app.api.models.ai_collection import AiCollection
from app.api.schemas.base_request import RequestType
from app.api.schemas.ip_domain_requests import WebRequest, NetworkRequest
from app.api.info_gathering.InfoGather import InfoGather
from app.api.vulnerability_assesment.VulnerabilityAssessment import VulnerabilityAssessment
from app.api.exploiting.Exploiting import Exploiting

MODEL_API_URL = os.getenv("MODEL_API_URL", "http://host.docker.internal:8080/chat")
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


async def _store_report(report_type: str, target: str, prompt: str, result: Dict[str, Any]):
    ai_collection = AiCollection(
        report_type=report_type,
        target=target,
        prompt=prompt,
        resutlt=result
    )
    await ai_collection.save()

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
    
    try:
        prompt = await build_web_prompt(domain)
        result = await _call_llm(prompt)
        await _store_report("web", domain, prompt, result)
        return JSONResponse({"output": result})
    except Exception as e:
        raise HTTPException(502, f"Risk report error: {e}")

@router.post("/network_ai_risk_report", response_class=JSONResponse)
async def network_ai_risk_report(req: NetworkAIRiskRequest):
    ip = req.ip_address.strip()
    if not ip:
        raise HTTPException(400, "IP address cannot be empty")
    
    try:
        prompt = await build_network_prompt(ip)
        result = await _call_llm(prompt)
        await _store_report("network", ip, prompt, result)
        return JSONResponse({"output": result})
    except Exception as e:
        raise HTTPException(502, f"Risk report error: {e}")

@router.post("/web_gemini", status_code=status.HTTP_200_OK)
async def web_gemini(
    req: GeminiWebRequest | None = Body(None),
    domain: str | None = Query(None, alias="content", description="Domain if no body sent"),
):
    """Generate a web application penetration test report using Gemini AI"""
    
    try:
        # Handle request parameters
        if req is None:
            if domain is None:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Domain required")
            req = GeminiWebRequest(domain=domain)

        # Import required modules
        from app.ai_model.gemini.get_webdata import get_webtarget_data, build_gemini_web_prompt, PromptConfig

        # Get web target data
        data = await get_webtarget_data(req.domain)
        operational = data["operational"]
        
        # Configure prompt settings
        cfg = PromptConfig(
            executive_summary_words=req.executive_summary_words or 200,
            include_raw_block=req.include_raw_block if req.include_raw_block is not None else False,
            extra_sections=req.extra_sections or [],
        )
        
        # Build the prompt and call Gemini
        prompt = build_gemini_web_prompt(operational, cfg=cfg)
        llm_resp = await generate_content(model="gemini-2.5-pro", contents=prompt)
        
        # Extract report content
        report_md = llm_resp.get("text") or llm_resp.get("content") or "# Error: Empty response from AI model"

        # Build response
        response_data = {
            "domain": req.domain,
            "meta": data.get("meta", {}),
            "report_md": report_md,
            "llm_raw": llm_resp,
        }
        
        return JSONResponse(status_code=status.HTTP_200_OK, content=response_data)
        
    except HTTPException:
        raise
    except Exception as exc:
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
    
    try:
        # Handle request parameters
        if req is None:
            if ip_address is None:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "IP address required")
            req = GeminiNetworkRequest(ip_address=ip_address)

        # Import required modules
        from app.ai_model.gemini.get_networkdata import get_networktarget_data, build_gemini_network_prompt, PromptConfig

        # Get network target data
        data = await get_networktarget_data(req.ip_address)
        operational = data["operational"]
        
        # Configure prompt settings
        cfg = PromptConfig(
            executive_summary_words=req.executive_summary_words or 200,
            include_raw_block=req.include_raw_block if req.include_raw_block is not None else False,
            extra_sections=req.extra_sections or [],
        )
        
        # Build the prompt and call Gemini
        prompt = build_gemini_network_prompt(operational, cfg=cfg)
        llm_resp = await generate_content(model="gemini-2.5-pro", contents=prompt)
        
        # Extract report content
        report_md = llm_resp.get("text") or llm_resp.get("content") or "# Error: Empty response from AI model"

        # Build response
        response_data = {
            "ip_address": req.ip_address,
            "meta": data.get("meta", {}),
            "report_md": report_md,
            "llm_raw": llm_resp,
        }
        
        return JSONResponse(status_code=status.HTTP_200_OK, content=response_data)
        
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, 
            detail=f"Gemini model error: {str(exc)}"
        ) from exc