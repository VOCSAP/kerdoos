"""MCP server built for the /mcp mount of the WebUI app (ADR 0005)."""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from mcp.server import MCPServer
from mcp.server.auth.routes import create_protected_resource_routes
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.routing import Route

from kerdoos.config import Settings
from kerdoos.core.app.auth import AuthService
from kerdoos.interfaces.mcp.auth import KerdoosTokenVerifier
from kerdoos.interfaces.mcp.tools import register_tools

MOUNT_PATH = "/mcp"


def _public_url(settings: Settings) -> str:
    raw = settings.public_url
    if not raw:
        raise RuntimeError(
            "KERDOOS_MCP_ENABLED=true but KERDOOS_PUBLIC_URL is not set: the "
            "MCP server refuses to start without the URL its clients use, "
            "from which the Host allowlist is derived.")
    try:
        parts = urlsplit(raw)
        parts.port
    except ValueError:
        parts = None
    if (parts is None or parts.scheme not in ("http", "https")
            or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.query or parts.fragment):
        raise RuntimeError(
            f"KERDOOS_PUBLIC_URL={raw!r} must be an http(s) URL with a host "
            "and no credentials, query or fragment.")
    return raw.rstrip("/")


def _allowed_hosts(settings: Settings, public_url: str) -> list[str]:
    for extra in settings.mcp_allowed_hosts:
        if "*" in extra:
            raise RuntimeError(
                f"KERDOOS_MCP_ALLOWED_HOSTS contains {extra!r}: wildcards are "
                "refused, list every accepted Host value explicitly.")
    parts = urlsplit(public_url)
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    port = parts.port or (443 if parts.scheme == "https" else 80)
    derived = [host, f"{host}:{port}"]
    return list(dict.fromkeys([*derived, *settings.mcp_allowed_hosts]))


def build_mcp_server(
    settings: Settings, auth_service: AuthService,
) -> tuple[MCPServer, Starlette, list[Route]]:
    """Return the server (whose session_manager the host lifespan must run),
    the ASGI app to mount at MOUNT_PATH, and the discovery routes the host
    app must serve at its own root. Raises RuntimeError on an unusable
    KERDOOS_PUBLIC_URL or KERDOOS_MCP_ALLOWED_HOSTS."""
    public_url = _public_url(settings)
    allowed_hosts = _allowed_hosts(settings, public_url)
    auth = AuthSettings(
        issuer_url=public_url,
        resource_server_url=f"{public_url}{MOUNT_PATH}",
        # Kerdoos tokens carry no RFC 8707 resource: left unset, this
        # becomes True in mcp 3.0 and every token would be refused.
        validate_token_resource=False,
    )
    root = logging.getLogger()
    root_handlers, root_level = root.handlers[:], root.level
    try:
        mcp = MCPServer(
            name="kerdoos",
            token_verifier=KerdoosTokenVerifier(auth_service),
            auth=auth)
    finally:
        # MCPServer() calls logging.basicConfig, which would install its
        # own handler and level on the process-wide root logger.
        root.handlers[:] = root_handlers
        root.setLevel(root_level)
    register_tools(mcp)
    # The SDK serves this metadata inside the mounted sub-app, while the
    # 401 challenge advertises it at the host root.
    discovery_routes = create_protected_resource_routes(
        resource_url=auth.resource_server_url,
        authorization_servers=[auth.issuer_url],
        scopes_supported=auth.required_scopes)
    app = mcp.streamable_http_app(
        streamable_http_path="/",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts),
    )
    return mcp, app, discovery_routes
