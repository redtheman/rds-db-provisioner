"""Engine-specific SQL for PostgreSQL and MySQL/MariaDB.

Each engine takes ``connect(dbname)`` returning an autocommit DB-API
connection as the RDS master user. Identifiers have already been validated
against a strict pattern (see request.py) and are additionally quoted here.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import closing

from provisioner.passwords import scram_sha256_verifier
from provisioner.request import Request


class ProvisionError(RuntimeError):
    """The request is valid but cannot be applied safely to this database."""


def _rows(conn, sql: str, params: tuple = ()) -> list[tuple]:
    cur = conn.cursor()
    cur.execute(sql, params)
    return list(cur.fetchall()) if cur.description else []  # DDL has no result set


# --------------------------------------------------------------------------- #
# PostgreSQL (15+)
# --------------------------------------------------------------------------- #
PG_PRIVS = {
    "readonly": ("SELECT", "SELECT"),
    "readwrite": ("SELECT, INSERT, UPDATE, DELETE", "USAGE, SELECT, UPDATE"),
}


def pg_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def pg_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class Postgres:
    name = "postgres"

    def __init__(self, connect: Callable[[str], object], admin_db: str = "postgres"):
        self.connect = connect
        self.admin_db = admin_db

    def role_exists(self, req: Request) -> bool:
        with closing(self.connect(self.admin_db)) as conn:
            return bool(_rows(conn, "SELECT 1 FROM pg_roles WHERE rolname = %s", (req.role,)))

    def _ensure_member(self, conn, role: str, steps: list[str]) -> None:
        """RDS masters aren't superusers. In PG16+, CREATE DATABASE ... OWNER and
        ALTER DEFAULT PRIVILEGES FOR ROLE need membership in the target role."""
        pg16 = int(_rows(conn, "SHOW server_version_num")[0][0]) >= 160000
        # PG16 auto-grants a CREATEROLE user ADMIN on roles it creates, but without SET/INHERIT,
        # so "is a member" is not enough: check the specific abilities we need.
        checks = ("SET", "USAGE") if pg16 else ("MEMBER", "USAGE")
        if all(_rows(conn, f"SELECT pg_has_role(current_user, %s, '{c}')", (role,))[0][0] for c in checks):
            return
        options = " WITH INHERIT TRUE, SET TRUE" if pg16 else ""
        try:
            _rows(conn, f"GRANT {pg_ident(role)} TO CURRENT_USER{options}")
        except Exception as exc:
            raise ProvisionError(
                f"master user cannot act as role {role!r}: grant it ADMIN on that role, or "
                f"run 'GRANT {role} TO <master>' as the role's creator ({exc})"
            ) from exc
        steps.append(f"granted role {role} to master user (required to act for it)")

    def provision(self, req: Request, password: str | None) -> list[str]:
        steps: list[str] = []
        role, db = pg_ident(req.role), pg_ident(req.database)
        with closing(self.connect(self.admin_db)) as conn:
            exists = bool(_rows(conn, "SELECT 1 FROM pg_roles WHERE rolname = %s", (req.role,)))
            if password is not None:
                verifier = pg_literal(scram_sha256_verifier(password))
                verb = "ALTER" if exists else "CREATE"
                _rows(conn, f"{verb} ROLE {role} WITH LOGIN PASSWORD {verifier}")
                steps.append(f"{'set new password for' if exists else 'created'} role {req.role} (SCRAM-SHA-256)")
            else:
                steps.append(f"role {req.role} already exists; password unchanged")

            found = _rows(conn, "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = %s",
                          (req.database,))
            owner = found[0][0] if found else None

            if req.access == "owner":
                if owner is None:
                    self._ensure_member(conn, req.role, steps)
                    _rows(conn, f"CREATE DATABASE {db} OWNER {role}")
                    _rows(conn, f"REVOKE ALL ON DATABASE {db} FROM PUBLIC")
                    steps.append(f"created database {req.database} owned by {req.role}; revoked PUBLIC access")
                elif owner != req.role:
                    raise ProvisionError(
                        f"database {req.database} already exists and is owned by {owner}; refusing to change "
                        "ownership. Use access=readwrite or readonly instead."
                    )
                else:
                    steps.append(f"database {req.database} already owned by {req.role}")
                return steps

            if owner is None:
                raise ProvisionError(f"database {req.database} does not exist; create it with access=owner first")
            _rows(conn, f"GRANT CONNECT ON DATABASE {db} TO {role}")
            self._ensure_member(conn, owner, steps)

        table_privs, seq_privs = PG_PRIVS[req.access]
        with closing(self.connect(req.database)) as conn:
            for schema in req.schemas:
                if not _rows(conn, "SELECT 1 FROM pg_namespace WHERE nspname = %s", (schema,)):
                    raise ProvisionError(f"schema {schema} does not exist in {req.database}")
                s = pg_ident(schema)
                for sql in (
                    f"GRANT USAGE ON SCHEMA {s} TO {role}",
                    f"GRANT {table_privs} ON ALL TABLES IN SCHEMA {s} TO {role}",
                    f"GRANT {seq_privs} ON ALL SEQUENCES IN SCHEMA {s} TO {role}",
                    (
                        f"ALTER DEFAULT PRIVILEGES FOR ROLE {pg_ident(owner)} IN SCHEMA {s} "
                        f"GRANT {table_privs} ON TABLES TO {role}"
                    ),
                    (
                        f"ALTER DEFAULT PRIVILEGES FOR ROLE {pg_ident(owner)} IN SCHEMA {s} "
                        f"GRANT {seq_privs} ON SEQUENCES TO {role}"
                    ),
                ):
                    _rows(conn, sql)
                steps.append(f"granted {req.access} on schema {schema} (existing + future objects of {owner})")
        return steps


# --------------------------------------------------------------------------- #
# MySQL / MariaDB
# --------------------------------------------------------------------------- #
MYSQL_PRIVS = {
    "owner": "ALL PRIVILEGES",
    "readwrite": "SELECT, INSERT, UPDATE, DELETE, EXECUTE, CREATE TEMPORARY TABLES, LOCK TABLES, SHOW VIEW",
    "readonly": "SELECT, SHOW VIEW",
}


def my_ident(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


class MySQL:
    name = "mysql"

    def __init__(self, connect: Callable[[str | None], object]):
        self.connect = connect

    def role_exists(self, req: Request) -> bool:
        with closing(self.connect(None)) as conn:
            return bool(_rows(conn, "SELECT 1 FROM mysql.user WHERE User = %s AND Host = %s",
                              (req.role, req.user_host)))

    def provision(self, req: Request, password: str | None) -> list[str]:
        steps: list[str] = []
        account = (req.role, req.user_host)
        with closing(self.connect(None)) as conn:
            db_exists = bool(_rows(conn, "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = %s",
                                   (req.database,)))
            if not db_exists:
                if req.access != "owner":
                    raise ProvisionError(f"database {req.database} does not exist; create it with access=owner first")
                _rows(conn, f"CREATE DATABASE {my_ident(req.database)} CHARACTER SET utf8mb4")
                steps.append(f"created database {req.database} (utf8mb4)")

            exists = bool(_rows(conn, "SELECT 1 FROM mysql.user WHERE User = %s AND Host = %s", account))
            if password is not None:
                verb = "ALTER" if exists else "CREATE"
                _rows(conn, f"{verb} USER %s@%s IDENTIFIED BY %s", (*account, password))
                steps.append(f"{'set new password for' if exists else 'created'} user {req.role}@{req.user_host}")
            else:
                steps.append(f"user {req.role}@{req.user_host} already exists; password unchanged")
            if req.require_tls:
                _rows(conn, "ALTER USER %s@%s REQUIRE SSL", account)
                steps.append("require TLS for this user")

            _rows(conn, f"GRANT {MYSQL_PRIVS[req.access]} ON {my_ident(req.database)}.* TO %s@%s", account)
            steps.append(f"granted {req.access} on {req.database}.*")
        return steps
