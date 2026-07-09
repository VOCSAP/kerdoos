"""Kerdoos identity + auth (Phase 3, ADR 0001 S6).

Ports (PasswordHasher, AuthStore) + core AuthService live here / in core.app.
Concrete adapters (Argon2Hasher, SqliteAuthStore) are wired at the composition
root (CLI). The concurrent verify_* path uses per-operation connections
(SqliteAuthStore), never the single shared SqliteConfigStore connection.
"""
