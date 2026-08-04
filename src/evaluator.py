"""
Zero-Trust Access Control & Dynamic Permission Evaluator Engine.

Uses standard library dataclasses to eliminate binary cross-platform dependencies.
Implements Bitwise RBAC actions, Role DAG BFS traversal, and ABAC dynamic checks.
"""

from collections import deque
from dataclasses import dataclass, field
from enum import IntFlag, auto
import ipaddress
import time
from typing import Dict, List, Optional, Set, TypedDict


class Actions(IntFlag):
    """Bitwise representation of granular permissions for O(1) binary evaluation."""
    NONE = 0
    READ = auto()     # 1
    WRITE = auto()    # 2
    EXECUTE = auto()  # 4
    DELETE = auto()   # 8


@dataclass
class EvaluationContext:
    """Contextual attributes for ABAC dynamic evaluation."""
    request_timestamp: int
    source_ip: str
    device_trust_level: int


@dataclass
class AccessRequest:
    """Incoming authorization request object."""
    user_id: str
    assigned_roles: List[str]
    requested_action: Actions
    context: EvaluationContext


@dataclass
class RoleNode:
    """Node definition in the Role Hierarchy DAG."""
    role_name: str
    allowed_actions: Actions = Actions.NONE
    denied_actions: Actions = Actions.NONE
    parents: List[str] = field(default_factory=list)


class AccessDecision(TypedDict):
    """Output contract for access evaluation decision."""
    decision: str  # "ALLOW" | "DENY"
    reason: str
    execution_time_us: float


class DynamoDBRoleStore:
    """Manages role graph fetching with real-time stream cache invalidation."""

    def __init__(self, table_name: str, cache_ttl_seconds: int = 300):
        import boto3
        self.table_name = table_name
        self._cache_ttl = cache_ttl_seconds
        self._dynamodb = boto3.resource("dynamodb")
        self._table = self._dynamodb.Table(self.table_name)
        self._cache: Dict[str, RoleNode] = {}
        self._last_cache_update: float = 0.0
        self._local_cache_version: int = 0

    def _get_remote_cache_version(self) -> int:
        """Fetch current cache version token from DynamoDB system metadata."""
        try:
            response = self._table.get_item(
                Key={"PK": "SYSTEM#CONFIG", "SK": "CACHE_VERSION"}
            )
            item = response.get("Item", {})
            return int(item.get("version", 0))
        except Exception:
            return self._local_cache_version

    def _is_cache_stale(self) -> bool:
        # Check 1: Time-To-Live expiration
        if (time.time() - self._last_cache_update) > self._cache_ttl:
            return True

        # Check 2: Stream-triggered version bump check
        remote_version = self._get_remote_cache_version()
        if remote_version > self._local_cache_version:
            self._local_cache_version = remote_version
            return True

        return False

    def fetch_role_dag(self) -> Dict[str, RoleNode]:
        """Fetch role graph or return valid cached instance."""
        if self._cache and not self._is_cache_stale():
            return self._cache

        role_dag: Dict[str, RoleNode] = {}

        try:
            response = self._table.scan()
            items = response.get("Items", [])

            while "LastEvaluatedKey" in response:
                response = self._table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
                items.extend(response.get("Items", []))

            for item in items:
                pk = item.get("PK", "")
                sk = item.get("SK", "")

                if not pk.startswith("ROLE#"):
                    continue

                role_name = pk.replace("ROLE#", "")
                if role_name not in role_dag:
                    role_dag[role_name] = RoleNode(role_name=role_name)

                if sk == "METADATA":
                    role_dag[role_name].allowed_actions = Actions(int(item.get("allowed_actions", 0)))
                    role_dag[role_name].denied_actions = Actions(int(item.get("denied_actions", 0)))
                elif sk.startswith("PARENT#"):
                    parent_name = item.get("parent_role", sk.replace("PARENT#", ""))
                    role_dag[role_name].parents.append(parent_name)

            self._cache = role_dag
            self._last_cache_update = time.time()
            return self._cache

        except Exception as err:
            if self._cache:
                return self._cache
            raise RuntimeError(f"DynamoDB synchronization failure: {str(err)}") from err


class ZeroTrustEvaluator:
    """Evaluates RBAC+ABAC rules against Zero-Trust dynamic context."""

    def __init__(self, role_store: DynamoDBRoleStore, allowed_ip_subnets: List[str]):
        self.role_store = role_store
        self.allowed_networks = [ipaddress.ip_network(net) for net in allowed_ip_subnets]

    def _resolve_inherited_permissions(self, initial_roles: List[str], role_dag: Dict[str, RoleNode]) -> tuple[Actions, Actions]:
        visited: Set[str] = set()
        queue = deque(initial_roles)

        effective_allows = Actions.NONE
        effective_denies = Actions.NONE

        while queue:
            current_role_name = queue.popleft()

            if current_role_name in visited:
                continue
            visited.add(current_role_name)

            role_node = role_dag.get(current_role_name)
            if not role_node:
                continue

            effective_allows |= role_node.allowed_actions
            effective_denies |= role_node.denied_actions

            for parent in role_node.parents:
                if parent not in visited:
                    queue.append(parent)

        return effective_allows, effective_denies

    def _evaluate_abac_constraints(self, context: EvaluationContext) -> tuple[bool, str]:
        if context.device_trust_level < 3:
            return False, "ABAC_DENY: Device trust level below required minimum (3)"

        try:
            client_ip = ipaddress.ip_address(context.source_ip)
            if not any(client_ip in net for net in self.allowed_networks):
                return False, f"ABAC_DENY: Source IP {context.source_ip} outside authorized subnets"
        except ValueError:
            return False, f"ABAC_DENY: Malformed IP address format {context.source_ip}"

        return True, "ABAC_PASSED"

    def evaluate_access(self, request: AccessRequest) -> AccessDecision:
        start_time = time.perf_counter()

        role_dag = self.role_store.fetch_role_dag()
        effective_allows, effective_denies = self._resolve_inherited_permissions(request.assigned_roles, role_dag)

        if bool(effective_denies & request.requested_action):
            elapsed_us = (time.perf_counter() - start_time) * 1_000_000
            return AccessDecision(
                decision="DENY",
                reason=f"RBAC_EXPLICIT_DENY: Action {request.requested_action.name} denied by policy",
                execution_time_us=round(elapsed_us, 2)
            )

        if not bool(effective_allows & request.requested_action):
            elapsed_us = (time.perf_counter() - start_time) * 1_000_000
            return AccessDecision(
                decision="DENY",
                reason=f"RBAC_IMPLICIT_DENY: Action {request.requested_action.name} not permitted in hierarchy",
                execution_time_us=round(elapsed_us, 2)
            )

        abac_passed, abac_reason = self._evaluate_abac_constraints(request.context)
        elapsed_us = (time.perf_counter() - start_time) * 1_000_000

        if not abac_passed:
            return AccessDecision(
                decision="DENY",
                reason=abac_reason,
                execution_time_us=round(elapsed_us, 2)
            )

        return AccessDecision(
            decision="ALLOW",
            reason="ACCESS_GRANTED: RBAC and ABAC context satisfied",
            execution_time_us=round(elapsed_us, 2)
        )