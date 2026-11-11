"""Lambda entry point.

Example events:
    {"db_instance": "orders-prod", "database": "orders", "role": "orders_app", "access": "owner"}
    {"db_instance": "orders-prod", "database": "orders", "role": "bi_reader", "access": "readonly"}
"""

from __future__ import annotations

import json
import logging
import os
import ssl

import boto3

from provisioner.engines import MySQL, Postgres, ProvisionError
from provisioner.provision import Endpoint, run
from provisioner.request import Request, RequestError
from provisioner.secrets_store import SecretStore

log = logging.getLogger()
log.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

ENGINE_FAMILY = {
    "postgres": "postgres", "aurora-postgresql": "postgres",
    "mysql": "mysql", "mariadb": "mysql", "aurora-mysql": "mysql",
}
DEFAULT_CA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rds-ca", "global-bundle.pem")


def tls_context() -> ssl.SSLContext:
    """Verify the RDS certificate against the RDS CA bundle. Fail closed if it is missing."""
    bundle = os.environ.get("RDS_CA_BUNDLE", DEFAULT_CA)
    if os.path.exists(bundle):
        return ssl.create_default_context(cafile=bundle)
    if os.environ.get("ALLOW_UNVERIFIED_TLS") == "true":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        log.warning("RDS CA bundle not found; TLS is encrypted but NOT verified")
        return ctx
    raise ProvisionError(f"RDS CA bundle not found at {bundle}; run `make ca-bundle` before deploying")


def handler(event, context):
    try:
        req = Request.from_event(event)
        session = boto3.session.Session()
        rds, sm = session.client("rds"), session.client("secretsmanager")

        inst = rds.describe_db_instances(DBInstanceIdentifier=req.db_instance)["DBInstances"][0]
        family = ENGINE_FAMILY.get(inst["Engine"])
        if family is None:
            raise ProvisionError(f"unsupported engine {inst['Engine']}")
        host, port = inst["Endpoint"]["Address"], int(inst["Endpoint"]["Port"])

        master_arn = (inst.get("MasterUserSecret") or {}).get("SecretArn") or os.environ.get("MASTER_SECRET_ARN")
        if not master_arn:
            raise ProvisionError("instance has no RDS-managed master secret; set MASTER_SECRET_ARN")
        master = json.loads(sm.get_secret_value(SecretId=master_arn)["SecretString"])
        ctx = tls_context()

        if family == "postgres":
            import pg8000.dbapi

            def connect(dbname):
                conn = pg8000.dbapi.connect(user=master["username"], password=master["password"], host=host,
                                            port=port, database=dbname, ssl_context=ctx, timeout=15)
                conn.autocommit = True
                return conn

            engine = Postgres(connect)
        else:
            import pymysql

            def connect(dbname):
                return pymysql.connect(user=master["username"], password=master["password"], host=host,
                                       port=port, database=dbname, ssl=ctx, autocommit=True, connect_timeout=15)

            engine = MySQL(connect)

        store = SecretStore(sm, os.environ.get("SECRET_PREFIX", "rds-app"), os.environ.get("SECRET_KMS_KEY_ID") or None)
        result = run(req, engine, store, Endpoint(host, port, family))
        log.info(json.dumps(result))
        return result
    except (RequestError, ProvisionError) as exc:
        log.error("refused: %s", exc)
        return {"status": "error", "error": str(exc)}
