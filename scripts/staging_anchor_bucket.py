"""Create the STAGING audit-anchor bucket (Stage 12): versioning, Object Lock in COMPLIANCE
mode with a default retention, and two least-privilege users.

* ``anchor-writer`` (the anchor job): read, list, put and set retention on anchors. It
  cannot delete (no delete markers either), change the bucket or bypass locks.
* ``anchor-reader`` (verification and monitoring): read and list only.

Runs inside the staging network with the object store's ROOT credentials, which only this
setup job holds. It is idempotent: an existing bucket is checked, never weakened.

The policy JSON is standard AWS IAM, so the same documents work on AWS S3. RustFS 1.0.0
applied a custom policy only when it also contained the ``sts:AssumeRole`` statement that
its built-in policies carry; without it, every request was denied. That statement is
included and is harmless on AWS.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from minio import Minio
from minio.commonconfig import COMPLIANCE
from minio.credentials import StaticProvider
from minio.minioadmin import MinioAdmin
from minio.objectlockconfig import DAYS, ObjectLockConfig

READ = [
    "s3:GetBucketLocation",
    "s3:GetBucketVersioning",
    "s3:GetBucketObjectLockConfiguration",
    "s3:ListBucket",
    "s3:ListBucketVersions",
]
READ_OBJECTS = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"]
WRITE_OBJECTS = ["s3:PutObject", "s3:PutObjectRetention"]


def policy(bucket: str, *, write: bool) -> dict[str, object]:
    objects = READ_OBJECTS + (WRITE_OBJECTS if write else [])
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": READ, "Resource": [f"arn:aws:s3:::{bucket}"]},
            {"Effect": "Allow", "Action": objects, "Resource": [f"arn:aws:s3:::{bucket}/*"]},
            {"Effect": "Allow", "Action": ["sts:AssumeRole"]},
        ],
    }


def _secret(name: str) -> str:
    return Path(os.environ[name]).read_text().strip()


def main() -> None:
    endpoint = os.environ["ANCHOR_S3_ENDPOINT"]
    bucket = os.environ["ANCHOR_S3_BUCKET"]
    days = int(os.environ.get("ANCHOR_RETENTION_DAYS", "1"))
    root_key, root_secret = os.environ["ANCHOR_ROOT_ACCESS_KEY"], _secret("ANCHOR_ROOT_SECRET_FILE")
    client = Minio(endpoint, access_key=root_key, secret_key=root_secret, secure=False)
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket, object_lock=True)
        client.set_object_lock_config(bucket, ObjectLockConfig(COMPLIANCE, days, DAYS))
        print(f"created bucket {bucket} (versioning + COMPLIANCE Object Lock, {days} d)")
    if client.get_bucket_versioning(bucket).status != "Enabled":
        sys.exit(f"{bucket} exists without versioning: refusing to use it for anchors")
    lock = client.get_object_lock_config(bucket)
    if lock.mode != COMPLIANCE:
        sys.exit(f"{bucket} Object Lock is {lock.mode}, not COMPLIANCE")
    admin = MinioAdmin(
        endpoint=endpoint, credentials=StaticProvider(root_key, root_secret), secure=False
    )
    with tempfile.TemporaryDirectory() as tmp:
        for name, write in (("anchor-writer", True), ("anchor-reader", False)):
            path = Path(tmp) / f"{name}.json"
            path.write_text(json.dumps(policy(bucket, write=write)))
            admin.policy_add(f"{name}-policy", str(path))
        admin.user_add("anchor-writer", _secret("ANCHOR_WRITER_SECRET_FILE"))
        admin.policy_set("anchor-writer-policy", user="anchor-writer")
        admin.user_add("anchor-reader", _secret("ANCHOR_READER_SECRET_FILE"))
        admin.policy_set("anchor-reader-policy", user="anchor-reader")
    print(
        f"bucket {bucket}: versioning Enabled, lock {lock.mode} {lock.duration} d; users "
        "anchor-writer (read/list/put/retention, no delete), anchor-reader (read/list)"
    )


if __name__ == "__main__":
    main()
