"""Admin-gated router (ADR 0001, post-MVP): every route requires a valid
session AND role == 'admin' (Depends(require_admin) attached at the ROUTER
level, rule FastAPI "auth au niveau router, jamais par endpoint").

Phase 4a: a minimal JSON stub (`/admin/whoami`) to prove the admin gate end
to end. Real admin use-cases (site catalogue CRUD, owner management) land in
later WebUI phases.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from kerdoos.core.app.services import Principal
from kerdoos.interfaces.web.deps import require_admin

router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])


@router.get("/whoami")
def whoami(principal: Principal = Depends(require_admin)) -> dict[str, str]:
    return {"owner_id": principal.owner_id, "role": principal.role}
