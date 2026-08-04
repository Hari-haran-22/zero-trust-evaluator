"""
DynamoDB Stream Triggered Cache Invalidator.
Listens for mutations in the Role Hierarchy table and increments global cache version.
"""

import os
import time
from typing import Any, Dict
import boto3

TABLE_NAME = os.environ.get("DYNAMODB_TABLE", "zero-trust-rbac-store-prod")
DYNAMODB = boto3.resource("dynamodb")
TABLE = DYNAMODB.Table(TABLE_NAME)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Process stream records and invalidate cache when role definitions change."""
    mutations_detected = False

    for record in event.get("Records", []):
        event_name = record.get("eventName")  # "INSERT" | "MODIFY" | "REMOVE"
        dynamo_data = record.get("dynamodb", {})
        keys = dynamo_data.get("Keys", {})
        pk = keys.get("PK", {}).get("S", "")

        # Skip system metadata to prevent endless loop updates
        if pk == "SYSTEM#CONFIG":
            continue

        if event_name in ("INSERT", "MODIFY", "REMOVE"):
            mutations_detected = True

    if mutations_detected:
        TABLE.put_item(
            Item={
                "PK": "SYSTEM#CONFIG",
                "SK": "CACHE_VERSION",
                "version": int(time.time()),
                "updated_at": str(time.time())
            }
        )
        return {"status": "SUCCESS", "message": "Global cache version updated"}

    return {"status": "NO_OP", "message": "No role DAG mutations detected"}