"""Locust Load Testing Suite for Zero-Trust Access Evaluator API."""

import json
import random
import time
from locust import HttpUser, between, task

class ZeroTrustEvaluatorUser(HttpUser):
    wait_time = between(0.01, 0.1)

    def on_start(self):
        """Prepare authentication headers and test payloads."""
        self.auth_headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sample_token_payload",
            "Content-Type": "application/json"
        }
        self.roles_pool = ["Developer", "SecurityLead", "Admin"]
        self.actions_pool = ["READ", "WRITE", "EXECUTE", "DELETE"]
        self.valid_subnets = ["10.0.1.15", "192.168.1.100"]
        self.invalid_subnets = ["203.0.113.5", "198.51.100.22"]

    @task(7)
    def test_valid_access_request(self):
        """Simulate high-frequency valid access evaluation (Cache Warm Hit)."""
        payload = {
            "user_id": f"user_{random.randint(1000, 9999)}",
            "assigned_roles": ["Developer"],
            "requested_action": "READ",
            "context": {
                "request_timestamp": int(time.time()),
                "source_ip": random.choice(self.valid_subnets),
                "device_trust_level": random.randint(3, 5)
            }
        }
        with self.client.post(
            "/evaluate",
            data=json.dumps(payload),
            headers=self.auth_headers,
            catch_response=True,
            name="Evaluate - Valid Request (ALLOW)"
        ) as response:
            if response.status_code == 200:
                res_data = response.json()
                if res_data.get("decision") == "ALLOW":
                    response.success()
                else:
                    response.failure(f"Unexpected DENY decision: {res_data.get('reason')}")
            else:
                response.failure(f"HTTP Error Status {response.status_code}: {response.text}")

    @task(3)
    def test_blocked_abac_access_request(self):
        """Simulate non-compliant client IP blocking (ABAC Deny)."""
        payload = {
            "user_id": f"user_{random.randint(1000, 9999)}",
            "assigned_roles": ["Developer"],
            "requested_action": "READ",
            "context": {
                "request_timestamp": int(time.time()),
                "source_ip": random.choice(self.invalid_subnets),
                "device_trust_level": 2  # Fail score
            }
        }
        with self.client.post(
            "/evaluate",
            data=json.dumps(payload),
            headers=self.auth_headers,
            catch_response=True,
            name="Evaluate - Untrusted Context (DENY)"
        ) as response:
            if response.status_code == 403:
                res_data = response.json()
                if res_data.get("decision") == "DENY":
                    response.success()
                else:
                    response.failure(f"Expected DENY but received: {res_data.get('decision')}")
            else:
                response.failure(f"Expected HTTP 403 but got {response.status_code}")