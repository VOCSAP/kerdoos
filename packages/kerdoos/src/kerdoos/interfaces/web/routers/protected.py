"""Auth-gated router (ADR 0001, post-MVP): every route requires a valid
signed session cookie (Depends(verify_session) attached at the ROUTER level,
rule FastAPI "auth au niveau router, jamais par endpoint" -- impossible to
add a route here and forget the dependency).

Phase 4a: a minimal JSON stub (`/me`) to prove the auth wiring end to end.
Real use-cases (config CRUD, run digest) land in later WebUI phases.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from kerdoos.core.app.services import Principal
from kerdoos.interfaces.web.deps import verify_session

router = APIRouter(dependencies=[Depends(verify_session)])


@router.get("/me")
def me(principal: Principal = Depends(verify_session)) -> dict[str, str]:
    return {"owner_id": principal.owner_id, "role": principal.role}
