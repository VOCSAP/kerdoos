"""Bearer authentication for the MCP interface.

The SDK's middleware parses the Authorization header and asks
KerdoosTokenVerifier; every rejection cause resolves to the same `None`.
Tools read their caller only through current_principal().
"""

from __future__ import annotations

import asyncio

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken

from kerdoos.core.app.auth import AuthService
from kerdoos.core.app.services import Principal


class KerdoosTokenVerifier:
    def __init__(self, auth_service: AuthService) -> None:
        self._auth = auth_service

    async def verify_token(self, token: str) -> AccessToken | None:
        principal = await asyncio.to_thread(self._auth.verify_bearer, token)
        if principal is None:
            return None
        return AccessToken(
            token=token, client_id=principal.owner_id,
            subject=principal.owner_id, scopes=[principal.role])


def current_principal() -> Principal:
    """The authenticated caller of the current MCP request.

    Raises PermissionError when no verified token is in scope: a tool never
    runs with a missing or partial identity.
    """
    access = get_access_token()
    if access is None or not access.subject or len(access.scopes) != 1:
        raise PermissionError("no authenticated principal for this MCP request")
    return Principal(owner_id=access.subject, role=access.scopes[0])
