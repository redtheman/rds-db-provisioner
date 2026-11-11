"""Application credentials in AWS Secrets Manager, in the standard RDS secret format."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError


class SecretStore:
    def __init__(self, sm, prefix: str = "rds-app", kms_key_id: str | None = None):
        self.sm = sm
        self.prefix = prefix.strip("/")
        self.kms_key_id = kms_key_id

    def name_for(self, db_instance: str, database: str, role: str) -> str:
        return f"{self.prefix}/{db_instance}/{database}/{role}"

    def _describe(self, name: str) -> dict | None:
        try:
            return self.sm.describe_secret(SecretId=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            raise

    def exists(self, name: str) -> str | None:
        """ARN of a live (not pending-deletion) secret, else None."""
        desc = self._describe(name)
        return desc["ARN"] if desc and not desc.get("DeletedDate") else None

    def put(self, name: str, value: dict, tags: dict | None = None) -> str:
        body = json.dumps(value)
        desc = self._describe(name)
        if desc is None:
            kwargs = {"Name": name, "SecretString": body,
                      "Description": "Application database credentials (managed by rds-db-provisioner)",
                      "Tags": [{"Key": k, "Value": v} for k, v in {"managed-by": "rds-db-provisioner",
                                                                   **(tags or {})}.items()]}
            if self.kms_key_id:
                kwargs["KmsKeyId"] = self.kms_key_id
            return self.sm.create_secret(**kwargs)["ARN"]
        if desc.get("DeletedDate"):
            self.sm.restore_secret(SecretId=name)
        self.sm.put_secret_value(SecretId=name, SecretString=body)
        return desc["ARN"]
