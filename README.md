# rds-db-provisioner

A Lambda that does the "new app needs a database" ticket in one call, the same way every time:

1. Connects to an **RDS PostgreSQL, MySQL or MariaDB** instance as the master user. The master credentials come from the RDS-managed secret, so nobody handles them.
2. Creates the application **login role** and the **database**.
3. Applies **least-privilege grants** for one of three access levels: `owner`, `readwrite` or `readonly`.
4. Generates a strong password and stores it in **Secrets Manager** in the standard RDS secret format, then returns the secret ARN. The password is never returned or logged.

```bash
aws lambda invoke --function-name <FunctionName> --cli-binary-format raw-in-base64-out \
  --payload '{"db_instance":"orders-prod","database":"orders","role":"orders_app","access":"owner"}' out.json
```

```json
{
  "status": "ok", "engine": "postgres", "database": "orders", "role": "orders_app", "access": "owner",
  "password_changed": true,
  "secret_arn": "arn:aws:secretsmanager:eu-west-1:111122223333:secret:rds-app/orders-prod/orders/orders_app-AbCdEf",
  "steps": [
    "created role orders_app (SCRAM-SHA-256)",
    "granted role orders_app to master user (required to act for it)",
    "created database orders owned by orders_app; revoked PUBLIC access"
  ]
}
```

## Access levels

| `access` | PostgreSQL | MySQL / MariaDB |
|---|---|---|
| `owner` | Creates the database **owned by the role**. The app runs its own migrations. `PUBLIC` loses `CONNECT`. | `ALL PRIVILEGES ON db.*` |
| `readwrite` | `CONNECT` and `USAGE`; `SELECT/INSERT/UPDATE/DELETE` on tables; sequence usage. **Default privileges** cover tables the owner creates later. | `SELECT, INSERT, UPDATE, DELETE, EXECUTE, CREATE TEMPORARY TABLES, LOCK TABLES, SHOW VIEW` |
| `readonly` | `CONNECT` and `USAGE`; `SELECT` on tables and sequences, plus default privileges for future tables | `SELECT, SHOW VIEW` |

`readwrite` and `readonly` require the database to exist already, so create it with `owner` first. Optional fields:

- `schemas` (PostgreSQL; default `["public"]`)
- `user_host` (MySQL; default `%`, for example `10.0.%`)
- `require_tls` (MySQL `REQUIRE SSL`)
- `rotate_password`
- `tags`

## Safety

- **Idempotent.** Re-running with the same input is safe. If the role and its secret both exist, the password is left alone. Pass `rotate_password: true` to issue a new one.
- **Secret first, SQL second.** If the SQL fails, a retry issues a fresh password, so the database and the secret can't drift apart.
- **The password never appears in SQL text.** For PostgreSQL it sends a pre-computed **SCRAM-SHA-256 verifier** instead of the password, so it can't leak through `log_statement = 'ddl'` or `pg_stat_statements`. For MySQL it's sent as a bound parameter.
- **No ownership takeover.** `owner` on an existing database owned by someone else is refused.
- **Strict identifiers.** Names must match `^[a-z_][a-z0-9_]{0,62}$`, reserved names (`postgres`, `rds_*`, `pg_*`, `root`, …) are rejected, and everything is quoted on top of that.
- **Verified TLS.** It connects using the RDS CA bundle and fails closed if the bundle is missing.
- **Least-privilege IAM.** It can read only `rds!*` master secrets and write only under its own prefix. In the VPC it reaches only the database ports on the DB security group.

### Works with a non-superuser master (RDS reality)

On RDS the master user is **not** a superuser. PostgreSQL 16 tightened the rules: a `CREATEROLE` user is automatically granted roles it creates *with ADMIN but without SET or INHERIT*. That's why `CREATE DATABASE … OWNER app` fails with `must be able to SET ROLE`. The provisioner checks for the specific abilities it needs (`SET`, `USAGE`) and grants itself membership `WITH INHERIT TRUE, SET TRUE` only when they're missing. On PostgreSQL 15 it falls back to plain membership.

## Deploy

```bash
make deploy            # downloads the RDS CA bundle, sam build, sam deploy --guided
```

Parameters: private `SubnetIds`, `VpcId`, the RDS `DatabaseSecurityGroupId` (an ingress rule from the Lambda is added), and optionally `SecretPrefix` and `SecretKmsKeyArn`. The subnets need a route to Secrets Manager and RDS APIs, through **VPC interface endpoints** (recommended) or NAT.

If an instance doesn't use RDS-managed master credentials, set `MASTER_SECRET_ARN` and widen the `ReadRdsManagedMasterSecrets` statement to that secret.

## Tests

The tests run against **real PostgreSQL 16 and MariaDB 10.11 servers with non-superuser, RDS-like master users**. They check that:

- the owner can log in with the generated password (which proves the SCRAM verifier) and run migrations
- the reader can `SELECT`, but can't write, including on tables created *after* the grant
- the writer can write but can't `DROP`
- a stranger role can't even connect once `PUBLIC` is revoked
- password rotation locks out the old password
- re-running changes nothing

```bash
pip install -r requirements-dev.txt
pytest -q                                   # unit tests; integration tests skip without servers
PG_TEST="host=127.0.0.1 port=5432 user=rdsmaster password=..." \
MYSQL_TEST="host=127.0.0.1 port=3306 user=admin password=..." pytest -q
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) starts both databases as service containers and runs the full suite.

## License

MIT
