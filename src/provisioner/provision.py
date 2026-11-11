"""Engine-independent orchestration: decide the password, store it first, then apply SQL."""

from __future__ import annotations

from dataclasses import dataclass

from provisioner.engines import ProvisionError
from provisioner.passwords import generate_password
from provisioner.request import Request


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    engine: str  # "postgres" | "mysql"


def run(req: Request, engine, store, endpoint: Endpoint) -> dict:
    secret_name = store.name_for(req.db_instance, req.database, req.role)
    role_exists = engine.role_exists(req)
    secret_arn = store.exists(secret_name)

    if role_exists and secret_arn and not req.rotate_password:
        password = None  # leave the working credentials alone
    elif role_exists and not secret_arn and not req.rotate_password:
        raise ProvisionError(
            f"role {req.role} already exists but has no secret at {secret_name}. Its password is unknown, "
            "so re-run with rotate_password=true to issue and store a new one."
        )
    else:
        password = generate_password()
        # Store first: if the SQL then fails, a retry simply issues a fresh password.
        secret_arn = store.put(
            secret_name,
            {
                "engine": endpoint.engine,
                "host": endpoint.host,
                "port": endpoint.port,
                "username": req.role,
                "password": password,
                "dbname": req.database,
                "dbInstanceIdentifier": req.db_instance,
            },
            tags={"db-instance": req.db_instance, "database": req.database, "access": req.access, **req.tags},
        )

    steps = engine.provision(req, password)
    return {
        "status": "ok",
        "engine": endpoint.engine,
        "db_instance": req.db_instance,
        "database": req.database,
        "role": req.role,
        "access": req.access,
        "password_changed": password is not None,
        "secret_arn": secret_arn,
        "steps": steps,
    }
