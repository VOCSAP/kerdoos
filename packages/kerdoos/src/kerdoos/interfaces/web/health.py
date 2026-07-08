"""Public, unauthenticated health router.

Kept separate from any future protected router (rule FastAPI "auth au niveau
router" -- a public endpoint lives on its own APIRouter with no auth
dependency, never as a `dependencies=[]` override on a protected router).
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
