# Aether Ops: Autonomous Security & Release Gate Agent

A production-ready reference architecture demonstrating how to build, evaluate, containerize, and securely govern multi-agent workflows using **Python ADK**, **Gemini 3.8**, **Google Cloud Run**, **SPIFFE Workload Identity**, **Cloud Run Agent Identity**, **Agent Registry**, and **Google Cloud Agent Gateway** with **IAP v2 Authorization Policies**.

---

## Security & Architecture Features
* **Stateless Runtimes**: Scales to zero on Cloud Run with decoupled session memory.
* **Semantic AI Policy Gate**: Uses Gemini (`gemini-3.8-flash`) to audit Kubernetes/GKE manifests for hardcoded secrets, obfuscated credentials, container breakout risks (`privileged: true`), network isolation bypasses (`hostNetwork: true`), and exposed public admin routes (`allUsers`).
* **Dual-Layer Zero-Trust Authentication**:
  * **Infrastructure Layer (Cloud Run Agent Identity & Agent Gateway)**: Cryptographically attested SPIFFE principals (`principal://agents.global.org-...`) governed by Google Cloud Agent Gateway, Agent Registry, and Identity-Aware Proxy (`roles/iap.egressor` + `roles/run.invoker`).
  * **Application Layer (SPIFFE JWT)**: Signed RFC 7518 HS256 SPIFFE Workload Tokens (`spiffe://aether.internal/ns/devops/sa/release-gate`) passed alongside Cloud Run `X-Serverless-Authorization` OIDC tokens.

---

## 1. Local Setup & Pre-Deployment Evaluations

### Install Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run Pre-Deployment Evaluations (`pytest`)
Both test modules automatically detect and execute inside `.venv/bin/python` even if run directly:
```bash
# Run full evaluation suite (SPIFFE Security Tests + Gemini LLM-as-a-Judge Evaluations)
.venv/bin/pytest

# Or run individual test suites directly
./tests/test_security.py
./tests/test_agent_evals.py
```

---

## 2. Local Container Demos (`run_demo_1.sh` – `run_demo_3.sh`)

### Build & Start Local Containers
```bash
docker network create aether-network 2>/dev/null || true

docker build -t aether-deployer-agent:latest -f Dockerfile.deployer .
docker build -t aether-ops-agent:latest -f Dockerfile .

docker rm -f deployer-container ops-container 2>/dev/null || true

docker run -d --name deployer-container \
  --network aether-network \
  -p 8081:8081 \
  aether-deployer-agent:latest

docker run -d --name ops-container \
  --user $(id -u):$(id -g) \
  --network aether-network \
  -p 8080:8080 \
  -v "${HOME}/.config/gcloud:/tmp/gcloud:ro" \
  -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcloud/application_default_credentials.json \
  -e DEPLOYER_AGENT_URL=http://deployer-container:8081 \
  -e PROJECT_ID=your-gcp-project-id \
  -e LOCATION=global \
  -e GEMINI_MODEL=gemini-3.8-flash \
  aether-ops-agent:latest
```

### Run Local Container Demo Scripts
Each `run_demo_*.sh` script targets the local container (`http://localhost:8080` $\rightarrow$ `http://deployer-container:8081`):
```bash
./run_demo_1.sh   # Demo 1: Rejects deployment-vulnerable.yaml
./run_demo_2.sh   # Demo 2: Approves deployment-compliant.yaml & dispatches to local deployer-container
./run_demo_3.sh   # Demo 3: Semantic audit rejects deployment-obfuscated.yaml
```

---

## 3. Cloud Run Deployment with Agent Identity

When deploying to Cloud Run with `--functional-type="agent"` and `--identity-type="agent-identity"`, Cloud Run automatically registers the workload as an AI Agent and assigns a dedicated **Agent Identity** principal instead of a traditional IAM service account.

### Step 3.1: Build & Push Container Images to Artifact Registry
```bash
PROJECT_ID="your-gcp-project-id"
REGION="us-central1"
REPO_NAME="aether-repo"

# 1. Build & push Deployer Agent
docker build -t us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/aether-deployer-agent:latest -f Dockerfile.deployer .
docker push us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/aether-deployer-agent:latest

# 2. Build & push Ops Agent
docker build -t us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/aether-ops-agent:latest -f Dockerfile .
docker push us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/aether-ops-agent:latest
```

### Step 3.2: Resolve Cloud Run Agent Identity Principals & Configure IAM Permissions
Because `--identity-type="agent-identity"` uses the service's `principal://` identity at startup to read Secret Manager secrets and invoke Vertex AI, grant the required permissions directly to the Agent Identity principals:

```bash
PROJECT_ID="your-gcp-project-id"
REGION="us-central1"

# Dynamically fetch Project Number and Organization ID
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")
ORG_ID=$(gcloud projects get-ancestors "${PROJECT_ID}" --format="value(id)" | tail -n 1)

# Construct the deterministic Cloud Run Agent Identity Principals
DEPLOYER_AGENT_PRINCIPAL="principal://agents.global.org-${ORG_ID}.system.id.goog/resources/run/projects/${PROJECT_NUMBER}/locations/${REGION}/services/aether-deployer-agent"
OPS_AGENT_PRINCIPAL="principal://agents.global.org-${ORG_ID}.system.id.goog/resources/run/projects/${PROJECT_NUMBER}/locations/${REGION}/services/aether-ops-agent"

echo "Deployer Agent Principal: ${DEPLOYER_AGENT_PRINCIPAL}"
echo "Ops Agent Principal:      ${OPS_AGENT_PRINCIPAL}"

# 1. Grant Secret Manager access ('aether-hmac-secret') to both Agent Identities
gcloud secrets add-iam-policy-binding aether-hmac-secret \
  --project="${PROJECT_ID}" \
  --member="${DEPLOYER_AGENT_PRINCIPAL}" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding aether-hmac-secret \
  --project="${PROJECT_ID}" \
  --member="${OPS_AGENT_PRINCIPAL}" \
  --role="roles/secretmanager.secretAccessor"

# 2. Grant Vertex AI User & Viewer roles to the Ops Agent Identity (for Gemini & Agent Registry/Gateway discovery)
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="${OPS_AGENT_PRINCIPAL}" \
  --role="roles/aiplatform.user" \
  --condition=None

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="${OPS_AGENT_PRINCIPAL}" \
  --role="roles/viewer" \
  --condition=None
```

### Step 3.3: Deploy Services to Cloud Run
```bash
# 1. Deploy Downstream Aether Deployer Agent
gcloud beta run deploy aether-deployer-agent \
  --project="your-gcp-project-id" \
  --image="us-central1-docker.pkg.dev/your-gcp-project-id/aether-repo/aether-deployer-agent:latest" \
  --region="us-central1" \
  --platform="managed" \
  --functional-type="agent" \
  --identity-type="agent-identity" \
  --allow-unauthenticated \
  --set-env-vars="ENVIRONMENT=production,ENFORCE_SPIFFE_AUTH=true" \
  --set-secrets="HMAC_SECRET=aether-hmac-secret:latest"

# 2. Grant Cloud Run Invoker on Deployer Agent to the Ops Agent Identity
gcloud beta run services add-iam-policy-binding aether-deployer-agent \
  --project="your-gcp-project-id" \
  --region="us-central1" \
  --member="${OPS_AGENT_PRINCIPAL}" \
  --role="roles/run.invoker"

# 3. Deploy Upstream Aether Ops Agent
DEPLOYER_URL=$(gcloud beta run services describe aether-deployer-agent \
  --project="your-gcp-project-id" \
  --region="us-central1" \
  --format="value(status.url)")

gcloud beta run deploy aether-ops-agent \
  --project="your-gcp-project-id" \
  --image="us-central1-docker.pkg.dev/your-gcp-project-id/aether-repo/aether-ops-agent:latest" \
  --region="us-central1" \
  --platform="managed" \
  --functional-type="agent" \
  --identity-type="agent-identity" \
  --allow-unauthenticated \
  --set-env-vars="ENVIRONMENT=production,ENFORCE_SPIFFE_AUTH=true,PROJECT_ID=your-gcp-project-id,LOCATION=global,GEMINI_MODEL=gemini-3.8-flash,DEPLOYER_AGENT_URL=${DEPLOYER_URL}" \
  --set-secrets="HMAC_SECRET=aether-hmac-secret:latest"
```

---

## 4. Google Cloud Agent Gateway, Agent Registry & IAP Policy Configuration

To govern agent-to-agent communication through **Google Cloud Agent Gateway** and **Agent Registry** with **IAP v2 Request Authorization**:

### Step 4.1: Provision Required GCP Service Agents
Ensure the project has service identities created for Network Services, Agent Registry, Network Security, and SaaS Service Management:
```bash
for svc in \
  networkservices.googleapis.com \
  agentregistry.googleapis.com \
  networksecurity.googleapis.com \
  saasservicemgmt.googleapis.com; do
  gcloud beta services identity create --service="${svc}" --project="your-gcp-project-id"
done
```

### Step 4.2: Register the Downstream Deployer Service in Agent Registry
Register `aether-deployer-agent` in Agent Registry so `aether-ops-agent` can dynamically discover its vetted endpoint URL and IAP resource path:
```bash
DEPLOYER_URL=$(gcloud beta run services describe aether-deployer-agent \
  --project="your-gcp-project-id" \
  --region="us-central1" \
  --format="value(status.url)")

gcloud alpha agent-registry services create aether-deployer-service \
  --project="your-gcp-project-id" \
  --location="us-central1" \
  --display-name="Aether Deployer Agent Service" \
  --endpoint-spec-type="no-spec" \
  --interfaces="url=${DEPLOYER_URL},protocolBinding=HTTP_JSON"

# Retrieve the generated Agent Registry Endpoint ID
REGISTRY_ENDPOINT_URI=$(gcloud alpha agent-registry services describe aether-deployer-service \
  --project="your-gcp-project-id" \
  --location="us-central1" \
  --format="value(registryResource)")
REGISTRY_ENDPOINT_ID=$(basename "${REGISTRY_ENDPOINT_URI}")
echo "Registry Endpoint ID: ${REGISTRY_ENDPOINT_ID}"
```

### Step 4.3: Create the Google Cloud Agent Gateway (`aether-ingress-agw`)
```bash
gcloud beta network-services agent-gateways import aether-ingress-agw \
  --project="your-gcp-project-id" \
  --location="us-central1" << 'EOF'
name: projects/your-gcp-project-id/locations/us-central1/agentGateways/aether-ingress-agw
description: Agent Gateway for Aether Ops & Deployer Agents
protocols:
  - MCP
googleManaged:
  governedAccessPath: CLIENT_TO_AGENT
EOF
```

### Step 4.4: Create the IAP Request Authz Service Extension & Bind Authz Policy to the Gateway
Configure an authorization extension targeting `iap.googleapis.com` (`iapPolicyVersion: "V2"`) and bind it to `aether-ingress-agw` via a `REQUEST_AUTHZ` policy:
```bash
# 1. Create the IAP Authorization Service Extension
gcloud beta service-extensions authz-extensions import aether-iap-authz-ext \
  --project="your-gcp-project-id" \
  --location="us-central1" << 'EOF'
name: aether-iap-authz-ext
service: iap.googleapis.com
failOpen: true
timeout: 1s
metadata:
  iapPolicyVersion: "V2"
  iamEnforcementMode: "DRY_RUN"
EOF

# 2. Bind the REQUEST_AUTHZ Policy to the Agent Gateway
gcloud network-security authz-policies import aether-iap-authz-policy \
  --project="your-gcp-project-id" \
  --location="us-central1" << 'EOF'
name: projects/your-gcp-project-id/locations/us-central1/authzPolicies/aether-iap-authz-policy
target:
  resources:
    - projects/your-gcp-project-id/locations/us-central1/agentGateways/aether-ingress-agw
policyProfile: REQUEST_AUTHZ
action: CUSTOM
customProvider:
  authzExtension:
    resources:
      - projects/your-gcp-project-id/locations/us-central1/authzExtensions/aether-iap-authz-ext
EOF
```

### Step 4.5: Grant `roles/iap.egressor` on the Agent Registry Endpoint to `aether-ops-agent`
Grant the `roles/iap.egressor` role on the registered `aether-deployer-service` endpoint to `aether-ops-agent`'s Agent Identity principal:
```bash
gcloud alpha iap web add-iam-policy-binding \
  --project="your-gcp-project-id" \
  --resource-type="agent-registry" \
  --region="us-central1" \
  --endpoint="${REGISTRY_ENDPOINT_ID}" \
  --member="${OPS_AGENT_PRINCIPAL}" \
  --role="roles/iap.egressor" \
  --condition=None
```

---

## 5. Production & Agent Gateway Verification Scripts

Because the organization enforces `constraints/run.managed.requireInvokerIam`, incoming requests to Cloud Run pass a Google OIDC Identity Token in the `X-Serverless-Authorization: Bearer <ID_TOKEN>` header while preserving the application's SPIFFE token in `Authorization: Bearer <SPIFFE_TOKEN>`.

```bash
# 1. Verify Cloud Run Services & Agent Gateway Health
./test_production_health.sh

# 2. Verify Live Cloud Run Semantic Rejection (Obfuscated Manifest)
./test_production_rejection.sh

# 3. Verify Live Cloud Run Compliant Deployment via Agent Gateway
./test_production_success.sh

# 4. Full Control-Plane & Data-Plane Agent Gateway + Agent Registry Verification Suite
./test_agent_gateway.sh
```
