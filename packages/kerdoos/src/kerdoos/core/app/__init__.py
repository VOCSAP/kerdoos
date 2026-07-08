"""Core use-cases layer (ADR 0001 S4).

AppService is the ONLY place business logic for mutating/reading tenant
config+state lives; interfaces (CLI/WebUI/MCP) call into it and stay thin
(invariant #9).
"""
