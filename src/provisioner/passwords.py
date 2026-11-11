"""Password generation and PostgreSQL SCRAM-SHA-256 verifiers.

Sending PostgreSQL a pre-computed SCRAM verifier instead of the plain-text
password means the password never appears in DDL text, so it cannot leak
through ``log_statement = 'ddl'`` or ``pg_stat_statements``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import string

# Excludes quotes, backslash, @, /, : and whitespace, which break connection
# strings and shell escaping.
ALPHABET = string.ascii_letters + string.digits + "-_.~!#%^*+="


def generate_password(length: int = 32) -> str:
    if length < 16:
        raise ValueError("password length must be at least 16")
    while True:
        pw = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw


def scram_sha256_verifier(password: str, iterations: int = 4096, salt: bytes | None = None) -> str:
    """Build the verifier PostgreSQL stores in pg_authid.rolpassword (RFC 5802 / 7677)."""
    salt = salt if salt is not None else os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"
