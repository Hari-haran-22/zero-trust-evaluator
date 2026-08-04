"""AWS Lambda Request Router processing request payload into Dataclass objects."""

import json
import os
from typing import Any, Dict
from evaluator import AccessRequest, Actions, DynamoDBRoleStore, EvaluationContext, ZeroTrustEvaluator

# Environment Variables & Singletons
TABLE_NAME = os.environ.get("DYNAMODB_TABLE", "zero-trust-rbac-store-prod")
CACHE_TTL = int(os.environ.get("CACHE_TTL_SECONDS", "300"))
ALLOWED_SUBNETS = json.loads(os.environ.get("ALLOWED_SUBNETS", '["10.0.0.0/16", "192.168.1.0/24"]'))

ROLE_STORE = DynamoDBRoleStore(table_name=TABLE_NAME, cache_ttl_seconds=CACHE_TTL)
EVALUATOR = ZeroTrustEvaluator(role_store=ROLE_STORE, allowed_ip_subnets=ALLOWED_SUBNETS)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    try:
        body_raw = event.get("body", "{}")
        body = json.loads(body_raw) if isinstance(body_raw, str) else body_raw

        context_dict = body.get("context", {})
        
        # Build dataclasses explicitly
        ctx = EvaluationContext(
            request_timestamp=int(context_dict.get("request_timestamp", 0)),
            source_ip=str(context_dict.get("source_ip", "")),
            device_trust_level=int(context_dict.get("device_trust_level", 0))
        )

        access_request = AccessRequest(
            user_id=str(body.get("user_id", "")),
            assigned_roles=list(body.get("assigned_roles", [])),
            requested_action=Actions[body.get("requested_action", "NONE").upper()],
            context=ctx
        )

        decision = EVALUATOR.evaluate_access(access_request)

        return {
            "statusCode": 200 if decision["decision"] == "ALLOW" else 403,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(decision)
        }

    except KeyError as ke:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": f"Invalid or missing action key: {str(ke)}"})
        }
    except Exception as exc:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": f"Internal Evaluation Error: {str(exc)}"})
        }