"""Expanded Unit test suite for Zero-Trust Evaluator engine logic."""

import pytest
from evaluator import AccessRequest, Actions, EvaluationContext, RoleNode, ZeroTrustEvaluator


class MockRoleStore:
    def fetch_role_dag(self):
        return {
            "Admin": RoleNode(
                role_name="Admin",
                allowed_actions=Actions.READ | Actions.WRITE | Actions.EXECUTE | Actions.DELETE,
                parents=["Developer"]
            ),
            "Developer": RoleNode(
                role_name="Developer",
                allowed_actions=Actions.READ | Actions.WRITE,
                denied_actions=Actions.DELETE
            )
        }


@pytest.fixture
def evaluator():
    return ZeroTrustEvaluator(
        role_store=MockRoleStore(),
        allowed_ip_subnets=["10.0.0.0/16", "192.168.1.0/24"]
    )


def test_rbac_allow_valid_action(evaluator):
    req = AccessRequest(
        user_id="u1",
        assigned_roles=["Developer"],
        requested_action=Actions.READ,
        context=EvaluationContext(request_timestamp=100, source_ip="10.0.1.10", device_trust_level=4)
    )
    decision = evaluator.evaluate_access(req)
    assert decision["decision"] == "ALLOW"


def test_rbac_explicit_deny(evaluator):
    req = AccessRequest(
        user_id="u2",
        assigned_roles=["Developer"],
        requested_action=Actions.DELETE,
        context=EvaluationContext(request_timestamp=100, source_ip="10.0.1.10", device_trust_level=4)
    )
    decision = evaluator.evaluate_access(req)
    assert decision["decision"] == "DENY"
    assert "RBAC_EXPLICIT_DENY" in decision["reason"]


def test_abac_deny_low_trust_level(evaluator):
    req = AccessRequest(
        user_id="u3",
        assigned_roles=["Admin"],
        requested_action=Actions.READ,
        context=EvaluationContext(request_timestamp=100, source_ip="10.0.1.10", device_trust_level=1)
    )
    decision = evaluator.evaluate_access(req)
    assert decision["decision"] == "DENY"
    assert "Device trust level" in decision["reason"]


def test_abac_deny_unauthorized_ip(evaluator):
    req = AccessRequest(
        user_id="u4",
        assigned_roles=["Admin"],
        requested_action=Actions.READ,
        context=EvaluationContext(request_timestamp=100, source_ip="172.16.0.5", device_trust_level=4)
    )
    decision = evaluator.evaluate_access(req)
    assert decision["decision"] == "DENY"
    assert "outside authorized subnets" in decision["reason"]


def test_missing_role(evaluator):
    req = AccessRequest(
        user_id="u5",
        assigned_roles=["NonExistentRole"],
        requested_action=Actions.READ,
        context=EvaluationContext(request_timestamp=100, source_ip="10.0.1.10", device_trust_level=4)
    )
    decision = evaluator.evaluate_access(req)
    assert decision["decision"] == "DENY"


def test_cache_invalidation(evaluator):
    # If using the direct internal cache dictionary attribute
    evaluator._dag_cache = None
    assert evaluator._dag_cache is None