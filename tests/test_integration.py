"""Run the engines against real servers with non-superuser, RDS-like master users.

    PG_TEST="host=127.0.0.1 port=5432 user=rdsmaster password=..."      (role with CREATEROLE CREATEDB)
    MYSQL_TEST="host=127.0.0.1 port=3306 user=admin password=..."         (ALL ON *.* WITH GRANT OPTION)
    pytest -q tests/test_integration.py
"""

import os
import uuid

import pg8000.exceptions
import pymysql.err
import pytest

from provisioner.engines import MySQL, Postgres, ProvisionError
from provisioner.passwords import generate_password
from provisioner.request import Request

PG_ERR = (pg8000.exceptions.DatabaseError, pg8000.exceptions.InterfaceError)
MY_ERR = pymysql.err.MySQLError


def _cfg(var):
    raw = os.environ.get(var)
    if not raw:
        pytest.skip(f"{var} not set")
    return dict(kv.split("=", 1) for kv in raw.split())


def _suffix():
    return uuid.uuid4().hex[:8]


# ----------------------------------------------------------------------------- #
@pytest.fixture
def pg():
    import pg8000.dbapi

    cfg = _cfg("PG_TEST")

    def connect(dbname, user=cfg["user"], password=cfg["password"]):
        conn = pg8000.dbapi.connect(user=user, password=password, host=cfg["host"], port=int(cfg["port"]),
                                    database=dbname)
        conn.autocommit = True
        return conn

    return connect


def _q(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur.fetchall() if cur.description else []


def test_postgres_owner_readonly_readwrite(pg):
    s = _suffix()
    db, owner, reader, writer = f"shop_{s}", f"shop_app_{s}", f"shop_ro_{s}", f"shop_rw_{s}"
    engine = Postgres(pg)

    owner_pw = generate_password()
    steps = engine.provision(Request.from_event({"db_instance": "local", "database": db, "role": owner}), owner_pw)
    assert any("created database" in x for x in steps)

    # The owner logs in with the plain password (proves the SCRAM verifier) and runs a migration.
    app = pg(db, owner, owner_pw)
    _q(app, "CREATE TABLE orders (id serial PRIMARY KEY, total numeric)")
    _q(app, "INSERT INTO orders (total) VALUES (10)")
    app.close()

    ro_pw, rw_pw = generate_password(), generate_password()
    engine.provision(Request.from_event({"db_instance": "local", "database": db, "role": reader,
                                         "access": "readonly"}), ro_pw)
    engine.provision(Request.from_event({"db_instance": "local", "database": db, "role": writer,
                                         "access": "readwrite"}), rw_pw)

    # A table created AFTER the grants must be covered by default privileges.
    app = pg(db, owner, owner_pw)
    _q(app, "CREATE TABLE refunds (id serial PRIMARY KEY, amount numeric)")
    app.close()

    ro = pg(db, reader, ro_pw)
    assert _q(ro, "SELECT count(*) FROM orders")[0][0] == 1
    assert _q(ro, "SELECT count(*) FROM refunds")[0][0] == 0
    with pytest.raises(PG_ERR):
        _q(ro, "INSERT INTO orders (total) VALUES (1)")
    ro.close()

    rw = pg(db, writer, rw_pw)
    _q(rw, "INSERT INTO refunds (amount) VALUES (5)")  # uses the sequence too
    _q(rw, "UPDATE orders SET total = 11")
    with pytest.raises(PG_ERR):
        _q(rw, "DROP TABLE orders")
    rw.close()

    # PUBLIC was revoked: a random login role can't even connect.
    stranger = f"stranger_{s}"
    admin = pg("postgres")
    _q(admin, f"CREATE ROLE {stranger} LOGIN PASSWORD 'Str4nger-pass-123'")
    admin.close()
    with pytest.raises(PG_ERR):
        pg(db, stranger, "Str4nger-pass-123")

    # Re-running is idempotent and leaves the password alone.
    again = engine.provision(Request.from_event({"db_instance": "local", "database": db, "role": owner}), None)
    assert any("already owned" in x for x in again)
    pg(db, owner, owner_pw).close()


def test_postgres_refuses_ownership_takeover(pg):
    s = _suffix()
    engine = Postgres(pg)
    engine.provision(Request.from_event({"db_instance": "local", "database": f"d_{s}", "role": f"a_{s}"}),
                     generate_password())
    with pytest.raises(ProvisionError, match="refusing to change ownership"):
        engine.provision(Request.from_event({"db_instance": "local", "database": f"d_{s}", "role": f"b_{s}"}),
                         generate_password())


def test_postgres_rotation(pg):
    s = _suffix()
    engine, req = Postgres(pg), Request.from_event({"db_instance": "local", "database": f"r_{s}", "role": f"r_{s}"})
    old, new = generate_password(), generate_password()
    engine.provision(req, old)
    engine.provision(req, new)
    pg(f"r_{s}", f"r_{s}", new).close()
    with pytest.raises(PG_ERR):
        pg(f"r_{s}", f"r_{s}", old)


# ----------------------------------------------------------------------------- #
@pytest.fixture
def my():
    import pymysql

    cfg = _cfg("MYSQL_TEST")

    def connect(dbname, user=cfg["user"], password=cfg["password"]):
        return pymysql.connect(user=user, password=password, host=cfg["host"], port=int(cfg["port"]),
                               database=dbname, autocommit=True)

    return connect


def test_mysql_owner_and_readonly(my):
    s = _suffix()
    db, owner, reader = f"crm_{s}", f"crm_app_{s}", f"crm_ro_{s}"
    engine = MySQL(my)
    owner_pw, ro_pw = generate_password(), generate_password()

    engine.provision(Request.from_event({"db_instance": "local", "database": db, "role": owner}), owner_pw)
    app = my(db, owner, owner_pw)
    _q(app, "CREATE TABLE leads (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(50))")
    _q(app, "INSERT INTO leads (name) VALUES ('a')")
    app.close()

    engine.provision(Request.from_event({"db_instance": "local", "database": db, "role": reader,
                                         "access": "readonly"}), ro_pw)
    ro = my(db, reader, ro_pw)
    assert _q(ro, "SELECT COUNT(*) FROM leads")[0][0] == 1
    with pytest.raises(MY_ERR):
        _q(ro, "INSERT INTO leads (name) VALUES ('b')")
    ro.close()

    with pytest.raises(ProvisionError, match="does not exist"):
        engine.provision(Request.from_event({"db_instance": "local", "database": f"nope_{s}", "role": reader,
                                             "access": "readonly"}), None)
