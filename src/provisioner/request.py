"""Validated provisioning request."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
HOST = re.compile(r"^[A-Za-z0-9.%_:-]{1,255}$")
ACCESS_LEVELS = ("owner", "readwrite", "readonly")


class RequestError(ValueError):
    """The event is invalid. Nothing has been changed."""


def _ident(value, field_name: str) -> str:
    if not isinstance(value, str) or not IDENT.match(value):
        raise RequestError(
            f"{field_name} must match {IDENT.pattern} (lower-case letters, digits, underscore; max 63)"
        )
    return value


@dataclass(frozen=True)
class Request:
    db_instance: str
    database: str
    role: str
    access: str = "owner"
    schemas: tuple[str, ...] = ("public",)
    user_host: str = "%"
    require_tls: bool = False
    rotate_password: bool = False
    tags: dict = field(default_factory=dict)

    @classmethod
    def from_event(cls, event: dict) -> Request:
        if not isinstance(event, dict):
            raise RequestError("event must be a JSON object")
        db_instance = event.get("db_instance")
        if not isinstance(db_instance, str) or not re.match(r"^[A-Za-z][A-Za-z0-9-]{0,62}$", db_instance):
            raise RequestError("db_instance must be an RDS DB instance identifier")
        access = event.get("access", "owner")
        if access not in ACCESS_LEVELS:
            raise RequestError(f"access must be one of {ACCESS_LEVELS}")
        schemas = tuple(_ident(s, "schemas[]") for s in event.get("schemas", ["public"]))
        if not schemas:
            raise RequestError("schemas must not be empty")
        user_host = event.get("user_host", "%")
        if not isinstance(user_host, str) or not HOST.match(user_host):
            raise RequestError("user_host must be a MySQL host pattern such as % or 10.0.%")
        tags = event.get("tags", {})
        if not isinstance(tags, dict):
            raise RequestError("tags must be an object")
        role = _ident(event.get("role"), "role")
        if role in {"postgres", "rdsadmin", "root", "admin", "mysql"} or role.startswith(("pg_", "rds_")):
            raise RequestError(f"role {role!r} is reserved")
        return cls(
            db_instance=db_instance,
            database=_ident(event.get("database"), "database"),
            role=role,
            access=access,
            schemas=schemas,
            user_host=user_host,
            require_tls=bool(event.get("require_tls", False)),
            rotate_password=bool(event.get("rotate_password", False)),
            tags={str(k): str(v) for k, v in tags.items()},
        )
