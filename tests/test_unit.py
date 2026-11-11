import json

import boto3
import pytest
from botocore.stub import ANY, Stubber

from provisioner.engines import ProvisionError, my_ident, pg_ident, pg_literal
from provisioner.passwords import ALPHABET, generate_password, scram_sha256_verifier
from provisioner.provision import Endpoint, run
from provisioner.request import Request, RequestError
from provisioner.secrets_store import SecretStore

BASE = {"db_instance": "orders-prod", "database": "orders", "role": "orders_app"}


# --- request validation ------------------------------------------------------
def test_defaults():
    r = Request.from_event(BASE)
    assert (r.access, r.schemas, r.user_host, r.rotate_password) == ("owner", ("public",), "%", False)


@pytest.mark.parametrize("patch", [
    {"role": "Orders"}, {"role": "x; DROP TABLE t"}, {"role": "a" * 64}, {"role": "postgres"},
    {"role": "rds_superuser"}, {"database": "orders-db"}, {"access": "admin"}, {"schemas": ["pub lic"]},
    {"schemas": []}, {"user_host": "10.0.0.1' OR 1=1"}, {"db_instance": "1bad"}, {"tags": "x"},
])
def test_rejects_bad_input(patch):
    with pytest.raises(RequestError):
        Request.from_event({**BASE, **patch})


# --- passwords -----------------------------------------------------------------
def test_password_shape():
    for _ in range(50):
        pw = generate_password()
        assert len(pw) == 32 and set(pw) <= set(ALPHABET)
        assert not set(pw) & set("'\"\\@/: ")


def test_scram_verifier_format_and_salt():
    v = scram_sha256_verifier("secret", salt=b"\x00" * 16)
    assert v.startswith("SCRAM-SHA-256$4096:AAAAAAAAAAAAAAAAAAAAAA==$")
    assert v == scram_sha256_verifier("secret", salt=b"\x00" * 16)
    assert v != scram_sha256_verifier("secret")


def test_quoting():
    assert pg_ident('a"b') == '"a""b"'
    assert pg_literal("it's") == "'it''s'"
    assert my_ident("a`b") == "`a``b`"


# --- orchestration -------------------------------------------------------------
class FakeEngine:
    def __init__(self, role_exists):
        self._exists = role_exists
        self.password = "unset"

    def role_exists(self, req):
        return self._exists

    def provision(self, req, password):
        self.password = password
        return ["did it"]


class FakeStore:
    def __init__(self, arn=None):
        self.arn, self.written = arn, None

    def name_for(self, *parts):
        return "/".join(("rds-app", *parts))

    def exists(self, name):
        return self.arn

    def put(self, name, value, tags=None):
        self.written = (name, value, tags)
        return "arn:new"


EP = Endpoint("db.example", 5432, "postgres")


def test_new_role_stores_secret_before_sql():
    eng, store = FakeEngine(False), FakeStore()
    out = run(Request.from_event(BASE), eng, store, EP)
    name, value, _ = store.written
    assert name == "rds-app/orders-prod/orders/orders_app"
    assert value["password"] == eng.password and value["username"] == "orders_app"
    assert out["password_changed"] and out["secret_arn"] == "arn:new"
    assert "password" not in json.dumps(out).replace("password_changed", "")


def test_existing_role_with_secret_is_left_alone():
    eng, store = FakeEngine(True), FakeStore(arn="arn:old")
    out = run(Request.from_event(BASE), eng, store, EP)
    assert eng.password is None and store.written is None and out["secret_arn"] == "arn:old"


def test_existing_role_without_secret_needs_rotation():
    with pytest.raises(ProvisionError, match="rotate_password"):
        run(Request.from_event(BASE), FakeEngine(True), FakeStore(), EP)


def test_rotation_issues_new_password():
    eng, store = FakeEngine(True), FakeStore(arn="arn:old")
    out = run(Request.from_event({**BASE, "rotate_password": True}), eng, store, EP)
    assert eng.password and out["password_changed"]


# --- secrets store ---------------------------------------------------------------
def _sm():
    return boto3.client("secretsmanager", region_name="eu-west-1", aws_access_key_id="x", aws_secret_access_key="x")


def test_store_creates_when_missing():
    sm = _sm()
    with Stubber(sm) as stub:
        stub.add_client_error("describe_secret", "ResourceNotFoundException", expected_params={"SecretId": "p/a"})
        stub.add_response("create_secret", {"ARN": "arn:a" + "x" * 20}, {
            "Name": "p/a", "SecretString": ANY, "Description": ANY, "Tags": ANY})
        assert SecretStore(sm, "p").put("p/a", {"k": "v"}).startswith("arn:a")


def test_store_restores_pending_deletion():
    sm = _sm()
    with Stubber(sm) as stub:
        stub.add_response("describe_secret", {"ARN": "arn:b" + "x" * 20, "DeletedDate": "2026-11-01"},
                          {"SecretId": "p/b"})
        stub.add_response("restore_secret", {}, {"SecretId": "p/b"})
        stub.add_response("put_secret_value", {}, {"SecretId": "p/b", "SecretString": ANY})
        SecretStore(sm, "p").put("p/b", {"k": "v"})
