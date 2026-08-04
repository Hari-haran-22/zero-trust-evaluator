"""
Administrative REST API Handler for Zero-Trust Role Graph Management.
Performs CRUD operations on Role Hierarchy DAG items in DynamoDB.
"""

from decimal import Decimal
import json
import os
from typing import Any, Dict
import boto3

TABLE_NAME = os.environ.get("DYNAMODB_TABLE", "zero-trust-rbac-store-prod")
DYNAMODB = boto3.resource("dynamodb")
TABLE = DYNAMODB.Table(TABLE_NAME)


class DecimalEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle boto3 DynamoDB Decimal types."""
    def default(self, obj: Any) -> Any:
        if isinstance(obj, Decimal):
            return int(obj) if obj % 1 == 0 else float(obj)
        return super().default(obj)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    route_key = event.get("routeKey", "")
    path_parameters = event.get("pathParameters", {}) or {}

    try:
        # GET /admin/roles - Fetch full Role Graph
        if route_key == "GET /admin/roles":
            response = TABLE.scan()
            items = response.get("Items", [])
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"roles": items}, cls=DecimalEncoder)
            }

        # POST /admin/roles - Create/Update Role Node
        elif route_key == "POST /admin/roles":
            body = json.loads(event.get("body", "{}"))
            role_name = body["role_name"]
            allowed_actions = int(body.get("allowed_actions", 0))
            denied_actions = int(body.get("denied_actions", 0))
            parents = body.get("parents", [])

            # Write Metadata item
            TABLE.put_item(
                Item={
                    "PK": f"ROLE#{role_name}",
                    "SK": "METADATA",
                    "allowed_actions": allowed_actions,
                    "denied_actions": denied_actions
                }
            )

            # Write Parent Edge items
            for parent in parents:
                TABLE.put_item(
                    Item={
                        "PK": f"ROLE#{role_name}",
                        "SK": f"PARENT#{parent}",
                        "parent_role": parent
                    }
                )

            return {
                "statusCode": 201,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"message": f"Role '{role_name}' created/updated successfully"})
            }

        # DELETE /admin/roles/{role_name} - Remove Role Node
        elif route_key == "DELETE /admin/roles/{role_name}":
            role_name = path_parameters.get("role_name", "")
            if not role_name:
                return {
                    "statusCode": 400,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({"error": "Missing path parameter 'role_name'"})
                }

            response = TABLE.query(
                KeyConditionExpression="PK = :pk",
                ExpressionAttributeValues={":pk": f"ROLE#{role_name}"}
            )

            with TABLE.batch_writer() as batch:
                for item in response.get("Items", []):
                    batch.delete_item(Key={"PK": item["PK"], "SK": item["SK"]})

            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"message": f"Role '{role_name}' deleted successfully"})
            }

        return {
            "statusCode": 404,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": f"Route not found: {route_key}"})
        }

    except Exception as exc:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": f"Admin API Failure: {str(exc)}"})
        }