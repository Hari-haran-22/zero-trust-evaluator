# Zero Trust Evaluator

## Key Technical Features

**O(1) Bitwise Permission Evaluation:**
Permissions are represented as integer bitmasks (`READ=1`, `WRITE=2`, `EXECUTE=4`, `DELETE=8`). Binary bitwise operations resolve inherited allowances and explicit denials across complex role hierarchies instantly.

**In-Memory Cache with Real-Time Stream Invalidation:**
DynamoDB Streams trigger an invalidator Lambda on role graph mutations (`INSERT`, `MODIFY`, or `DELETE`), updating a global `CACHE_VERSION` key to purge local container memory automatically across active Lambda instances.

**Zero External Binary Dependencies:**
Built entirely with Python 3.12 standard library `@dataclass` structures, avoiding platform-specific C/Rust binary compilation issues (e.g., `pydantic_core`) and keeping cold-start initialization times minimal.

**Infrastructure-as-Code (Terraform):**
Fully managed serverless infrastructure declared with Terraform, enforcing least-privilege IAM policies, CloudWatch log retention, real-time performance dashboards, and automated p95 latency alerts.

---

## 📊 Performance & Load Test Benchmark Results

Load testing executed via **Locust** against the live AWS environment (10 concurrent users, 1 minute duration):

| Metric | Measured Value | Target SLA |
|---|---|---|
| Total Requests Executed | 1,583 requests | > 1,000 |
| Success Rate | 100.00% (0 errors) | 99.90% |
| Average Throughput | 26.62 req/sec | > 20 req/s |
| p50 Median Response Latency | 290 ms | < 500 ms |
| p90 Percentile Latency | 310 ms | < 600 ms |
| p95 Percentile Latency | 320 ms | < 800 ms |
| p99 Percentile Latency | 500 ms | < 1,000 ms |

---

## 📡 REST API Reference

### 1. Access Evaluation Endpoint

**Endpoint:** `POST /evaluate`

**Description:** Evaluates dynamic authorization for a user request combining RBAC role inheritance and ABAC contextual factors (source IP subnet, device trust level, timestamp).

**Request Body:**
```json
{
  "user_id": "usr_992",
  "assigned_roles": ["Developer"],
  "requested_action": "READ",
  "context": {
    "request_timestamp": 1700000000,
    "source_ip": "10.0.1.15",
    "device_trust_level": 4
  }
}
```

**Response (HTTP 200 OK — Allowed):**
```json
{
  "decision": "ALLOW",
  "reason": "ACCESS_GRANTED: RBAC and ABAC context satisfied",
  "execution_time_us": 42.15
}
```

**Response (HTTP 403 Forbidden — Denied):**
```json
{
  "decision": "DENY",
  "reason": "ABAC_DENY: Device trust level below required minimum (3)",
  "execution_time_us": 38.80
}
```

---

### 2. Administrative Role Graph Management API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/admin/roles` | Export the complete role hierarchy DAG and permissions |
| `POST` | `/admin/roles` | Create or update a role node, its allowed/denied action bitmasks, and parent edges |
| `DELETE` | `/admin/roles/{role_name}` | Delete a role node and all associated graph links |

**Request Body (`POST /admin/roles`):**
```json
{
  "role_name": "DevOpsEngineer",
  "allowed_actions": 7,
  "denied_actions": 8,
  "parents": ["Developer"]
}
```

**Response (HTTP 201 Created):**
```json
{
  "message": "Role 'DevOpsEngineer' created/updated successfully"
}
```

---

## 📁 Repository Structure

```
zero-trust-evaluator/
├── src/
│   ├── evaluator.py       # Core Zero-Trust engine (Bitwise RBAC, ABAC, Cache Store)
│   ├── handler.py         # AWS Lambda handler for /evaluate API Gateway route
│   ├── admin_handler.py   # AWS Lambda handler for /admin/roles CRUD endpoints
│   └── invalidator.py     # Stream handler for real-time cache version bumping
├── terraform/
│   ├── main.tf            # Serverless resource declarations (Lambda, Gateway, DynamoDB)
│   ├── observability.tf   # CloudWatch Dashboards and p95 metric alarms
│   ├── variables.tf       # Infrastructure input variables
│   └── outputs.tf         # Output endpoints and resource ARNs
├── scripts/
│   └── seed_roles.py      # Python script to seed initial RBAC DAG into DynamoDB
├── tests/
│   └── locustfile.py      # Locust load testing suite
└── README.md
```

---

## 🛠️ Local Setup & Infrastructure Deployment

### Prerequisites

- Terraform v1.6.0+
- AWS CLI v2 configured with active AWS credentials
- Python 3.12+

### Step-by-Step Deployment

**1. Clone the Repository:**
```bash
git clone https://github.com/your-username/zero-trust-evaluator.git
cd zero-trust-evaluator
```

**2. Provision Infrastructure via Terraform:**
```bash
cd terraform
terraform init
terraform apply -auto-approve
cd ..
```

**3. Seed Initial Role Hierarchy into DynamoDB:**
```bash
python scripts/seed_roles.py
```

**4. Execute Performance Benchmark Suite:**
```bash
python -m locust -f tests/locustfile.py --host=https://YOUR_API_GATEWAY_URL --users=10 --spawn-rate=2 --run-time=1m --headless
```