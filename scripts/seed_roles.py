"""Populate initial Role Hierarchy DAG directly into AWS DynamoDB."""

import boto3

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("zero-trust-rbac-store-prod")

SEED_DATA = [
    # Admin Role Node
    {"PK": "ROLE#Admin", "SK": "METADATA", "allowed_actions": 15, "denied_actions": 0},  # READ|WRITE|EXECUTE|DELETE
    
    # SecurityLead Role Node
    {"PK": "ROLE#SecurityLead", "SK": "METADATA", "allowed_actions": 2, "denied_actions": 8},  # WRITE, DENY DELETE
    {"PK": "ROLE#SecurityLead", "SK": "PARENT#Admin", "parent_role": "Admin"},
    
    # Developer Role Node
    {"PK": "ROLE#Developer", "SK": "METADATA", "allowed_actions": 5, "denied_actions": 0},  # READ|EXECUTE
    {"PK": "ROLE#Developer", "SK": "PARENT#SecurityLead", "parent_role": "SecurityLead"}
]

with table.batch_writer() as batch:
    for item in SEED_DATA:
        batch.put_item(Item=item)

print("Successfully seeded role hierarchy into DynamoDB.")