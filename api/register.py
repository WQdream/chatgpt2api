from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from api.support import require_admin
from services.register_service import register_service


class RegisterConfigRequest(BaseModel):
    mail: dict | None = None
    proxy: str | None = None
    total: int | None = None
    threads: int | None = None
    mode: str | None = None
    target_quota: int | None = None
    target_available: int | None = None
    check_interval: int | None = None


class FreemailDomainsRequest(BaseModel):
    api_base: str
    jwt_token: str

class OutlookPoolResetRequest(BaseModel):
    scope: str | None = None


def create_router() -> APIRouter:
    router = APIRouter()

    @router.get("/api/register")
    async def get_register_config(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"register": register_service.get()}

    @router.post("/api/register")
    async def update_register_config(body: RegisterConfigRequest, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"register": register_service.update(body.model_dump(exclude_none=True))}

    @router.post("/api/register/start")
    async def start_register(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"register": register_service.start()}

    @router.post("/api/register/stop")
    async def stop_register(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"register": register_service.stop()}

    @router.post("/api/register/reset")
    async def reset_register(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"register": register_service.reset()}

    @router.post("/api/register/outlook-pool/reset")
    async def reset_outlook_pool(body: OutlookPoolResetRequest, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"register": register_service.reset_outlook_pool(body.scope or "all")}

    @router.post("/api/register/domain-health/reset")
    async def reset_domain_health(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"register": register_service.reset_domain_health()}

    @router.get("/api/register/events")
    async def register_events(token: str = ""):
        require_admin(f"Bearer {token}")

        async def stream():
            last = ""
            while True:
                payload = json.dumps(register_service.get(), ensure_ascii=False)
                if payload != last:
                    last = payload
                    yield f"data: {payload}\n\n"
                await asyncio.sleep(0.5)

        return StreamingResponse(stream(), media_type="text/event-stream")

    @router.post("/api/register/freemail/domains")
    async def fetch_freemail_domains(body: FreemailDomainsRequest, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        api_base = body.api_base.strip().rstrip("/")
        jwt_token = body.jwt_token.strip()
        if not api_base:
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail={"error": "api_base is required"})
        if not jwt_token:
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail={"error": "jwt_token is required"})
        from curl_cffi import requests as curl_requests
        session = curl_requests.Session(impersonate="chrome", verify=False)
        try:
            resp = session.get(
                f"{api_base}/api/domains",
                headers={"Authorization": f"Bearer {jwt_token}", "Accept": "application/json"},
                timeout=30,
            )
            if resp.status_code != 200:
                from fastapi import HTTPException
                raise HTTPException(status_code=502, detail={"error": f"Freemail 返回 HTTP {resp.status_code}: {resp.text[:200]}"})
            data = resp.json()
            if not isinstance(data, list):
                from fastapi import HTTPException
                raise HTTPException(status_code=502, detail={"error": "Freemail 返回格式异常，期望域名数组"})
            return {"domains": [str(item).strip() for item in data if str(item).strip()]}
        except Exception as exc:
            if hasattr(exc, "status_code"):
                raise
            from fastapi import HTTPException
            raise HTTPException(status_code=502, detail={"error": str(exc)}) from exc
        finally:
            session.close()

    return router
