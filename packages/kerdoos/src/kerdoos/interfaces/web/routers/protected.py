"""Placeholder for the future auth-gated router (ADR 0001, post-MVP).

Empty at Phase 0 (structural only -- no auth, no use-cases yet). Kept as its
own APIRouter from day one so the auth dependency can be attached at the
router level later (rule FastAPI "auth au niveau router, jamais par
endpoint") without having to retrofit every route with `Depends(...)`.
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
