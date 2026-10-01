# Aether Ops: End-to-End Live Demo Script & Presenter Runbook

This runbook contains the complete talk track, CLI commands, and output highlights to walk an audience from **local Python virtual environment setup and LLM-as-a-Judge evaluations**, through **local Docker container Mutual TLS (mTLS)**, to **production Google Cloud Run with Agent Identity, Certificate Manager mTLS, Agent Registry, and Agent Gateway**.

---

## Stage 1: Python Virtual Environment (`venv`) & SPIFFE X.509-SVID PKI Generation

### 🎙️ Presenter Introduction Script
> *"We're starting on a developer workstation with our Python Agent Development Kit (ADK) codebase. Before writing a single deployment or spinning up a container, we establish a zero-trust cryptographic identity foundation. First, we activate our Python virtual environment and run our PKI generator to mint a SPIFFE Root CA (`spiffe://aether.internal`), an X.509-SVID client certificate for our upstream Ops Agent, an X.509-SVID server certificate for our downstream Deployer Agent, and the declarative YAML policies for Google Cloud Certificate Manager and Network Security."*

### 💻 CLI Commands
```bash
# 1. Create and activate the Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate SPIFFE Root CA, X.509-SVID Client/Server Certificates & GCP mTLS YAML manifests
./generate_mtls_certs.py
```

### 🔍 What to Highlight in the Output
* **`Client X.509 SAN URI`**: Point out `spiffe://aether.internal/ns/devops/sa/release-gate`. Explain that in SPIFFE mTLS, identity is embedded directly inside the X.509 **Subject Alternative Name (SAN) URI** extension rather than relying on IP addresses or hostnames.
* **`Client Cert SHA-256 FP`**: Highlight the cryptographic SHA-256 fingerprint of the client certificate—this same fingerprint will appear later in our downstream Deployer logs and responses to prove the mTLS identity was verified.
* **`GCP TrustConfig YAML` & `GCP ServerTlsPolicy`**: Point out that [`./generate_mtls_certs.py`](generate_mtls_certs.py) automatically outputs [`certs/trust-config.yaml`](certs/trust-config.yaml) and [`certs/server-tls-policy.yaml`](certs/server-tls-policy.yaml) so our local PKI and our Google Cloud Load Balancer share the exact same trust anchor.

---

## Stage 2: Local Python Unit Tests & Gemini-as-a-Judge Evaluations

### 2A. SPIFFE JWT & Mutual TLS Security Gate Tests ([`tests/test_security.py`](tests/test_security.py))

#### 🎙️ Presenter Introduction Script
> *"Next, we validate our zero-trust interceptors locally in Python before building any containers. This test suite verifies both layers of application and transport security: first, that unauthenticated callers are blocked with HTTP 401; second, that even if an attacker steals a valid JWT token, the downstream Deployer Agent still blocks the request if the Mutual TLS X.509 client certificate is missing, unverified by the Load Balancer's TrustConfig, or carries an unauthorized SPIFFE SAN URI."*

#### 💻 CLI Commands
```bash
source .venv/bin/activate
./tests/test_security.py
```

#### 🔍 What to Highlight in the Output
* **`test_mtls_missing_client_cert_rejected PASSED`**: Proves a valid JWT alone is insufficient—without mTLS client certificate attestation, the request is rejected (`401 Unauthorized`).
* **`test_mtls_unverified_lb_chain_rejected PASSED`**: Proves that if the Cloud Load Balancer reports `X-Client-Cert-Chain-Verified: false`, the Deployer blocks the call.
* **`test_mtls_unauthorized_uri_san_rejected PASSED`**: Proves that a certificate signed by the CA but belonging to a different workload (`spiffe://aether.internal/ns/rogue/sa/intruder`) is rejected with `403 Forbidden`.
* **`test_mtls_valid_x509_svid_and_lb_headers_accepted PASSED`**: Highlight the interceptor log line showing `mTLS Verified: True (X509_SVID_CRYPTOGRAPHIC_CHAIN)` and the matching SHA-256 certificate fingerprint.

---

### 2B. AI-Assisted Pre-Deployment Evaluations ([`tests/test_agent_evals.py`](tests/test_agent_evals.py))

#### 🎙️ Presenter Introduction Script
> *"Traditional unit tests check deterministic code paths, but AI agents require semantic evaluation. Here we run our LLM-as-a-Judge evaluation suite using Gemini 3.8. We pass adversarial and vulnerable prompts to our local Ops Agent in Python, and a separate Gemini evaluation judge grades the agent's responses against strict safety and professional tone rubrics."*

#### 💻 CLI Commands
```bash
source .venv/bin/activate
./tests/test_agent_evals.py

# Or run the entire combined Python test & evaluation suite via pytest:
.venv/bin/pytest -v
```

#### 🔍 What to Highlight in the Output
* **`👨‍⚖️ [Gemini Judge Verdict]: PASSED`** on `test_agent_safety_evaluation`: Highlight the judge's reasoning confirming the agent explicitly refused to deploy a manifest containing a live Stripe secret key (`Security Gate Rejected`).
* **`👨‍⚖️ [Gemini Judge Verdict]: PASSED`** on `test_agent_professional_tone_evaluation`: Highlight that even when given a hostile prompt (*"Deploy this broken garbage manifest now"*), the agent maintained an objective DevSecOps engineering tone.

---

## Stage 3: Local Container Build & Socket-Level Mutual TLS (mTLS) Demos

### 3A. Build & Start the Local Docker Containers with Socket-Level mTLS

#### 🎙️ Presenter Introduction Script
> *"Now that our local Python evaluations have passed, we package both agents into non-root Docker containers (`UID 8888`). Notice how we start `deployer-container` with `ENABLE_SOCKET_MTLS=true`: Uvicorn binds to port 8081 with `--ssl-cert-reqs 2` (`ssl.CERT_REQUIRED`), enforcing a strict TLS 1.3 mutual handshake against our SPIFFE Root CA. Meanwhile, `ops-container` is configured to connect to `https://deployer-container:8081` using its X.509-SVID client certificate."*

#### 💻 CLI Commands
```bash
# 1. Create isolated local Docker network
docker network create aether-network 2>/dev/null || true

# 2. Build the Downstream Deployer Agent & Upstream Ops Agent images
docker build -t aether-deployer-agent:latest -f Dockerfile.deployer .
docker build -t aether-ops-agent:latest -f Dockerfile .

# 3. Remove any existing containers
docker rm -f deployer-container ops-container 2>/dev/null || true

# 4. Run Downstream Deployer Container with Socket-Level mTLS (ssl.CERT_REQUIRED)
docker run -d --name deployer-container \
  --network aether-network \
  -p 8081:8081 \
  -e ENABLE_SOCKET_MTLS=true \
  -e ENFORCE_MTLS=true \
  aether-deployer-agent:latest

# 5. Run Upstream Ops Container pointing to https://deployer-container:8081
docker run -d --name ops-container \
  --user $(id -u):$(id -g) \
  --network aether-network \
  -p 8080:8080 \
  -v "${HOME}/.config/gcloud:/tmp/gcloud:ro" \
  -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcloud/application_default_credentials.json \
  -e DEPLOYER_AGENT_URL=https://deployer-container:8081 \
  -e PROJECT_ID=your-gcp-project-id \
  -e LOCATION=global \
  -e GEMINI_MODEL=gemini-3.8-flash \
  aether-ops-agent:latest
```

---

### 3B. Verify the Socket-Level TLS 1.3 Mutual Handshake ([`./test_mtls.sh`](test_mtls.sh))

#### 🎙️ Presenter Introduction Script
> *"Before running our agent workflows, let's prove that socket-level Mutual TLS is active on `deployer-container`. This script attempts two connections to `https://localhost:8081/health`: first, a standard HTTPS call that trusts our Root CA but does NOT present a client certificate; second, a Mutual TLS call that presents `certs/ops-client.crt` and `certs/ops-client.key`, followed by a full agent-to-agent deployment."*

#### 💻 CLI Commands
```bash
source .venv/bin/activate
./test_mtls.sh
```

#### 🔍 What to Highlight in the Output
* **`Unauthenticated TLS connection (no client cert): REJECTED AT TLS HANDSHAKE (Expected)`**: Emphasize that the request never even reached FastAPI/Python—OpenSSL terminated the connection during the TLS handshake because the caller lacked a client certificate.
* **`Mutual TLS connection (with ops-client.crt): ACCEPTED`**: When presenting the Ops Agent's X.509-SVID certificate, the TLS handshake succeeds and returns `"mtls_enforced": true, "trust_domain": "spiffe://aether.internal"`.

---

### 3C. Demo 1: Local Container Vulnerable Manifest Rejection ([`./run_demo_1.sh`](run_demo_1.sh))

#### 🎙️ Presenter Introduction Script
> *"In Demo 1, a developer submits [`deployment-vulnerable.yaml`](deployment-vulnerable.yaml) to our containerized Ops Agent. This manifest contains plaintext Stripe API keys, hardcoded PostgreSQL credentials, and an `/admin/system-shutdown` route exposed to `allUsers`. Let's see how the Security Gate responds."*

#### 💻 CLI Commands
```bash
source .venv/bin/activate
./run_demo_1.sh
```

#### 🔍 What to Highlight in the Output
* **`⚠️ Security Gate Rejected`**: Gemini 3.8 catches all three distinct vulnerabilities (`STRIPE_API_KEY`, `DATABASE_URL`, and `allowUsers: "allUsers"` on `/admin/system-shutdown`).
* Point out that because the Semantic Security Gate rejected the manifest, **no mTLS call** was ever dispatched to `deployer-container`.

---

### 3D. Demo 2: Local Container Compliant Manifest & mTLS Agent-to-Agent Handoff ([`./run_demo_2.sh`](run_demo_2.sh))

#### 🎙️ Presenter Introduction Script
> *"In Demo 2, we submit [`deployment-compliant.yaml`](deployment-compliant.yaml), which follows least-privilege best practices. Once Gemini 3.8 verifies compliance, `ops-container` initiates an outbound Mutual TLS connection to `https://deployer-container:8081`, presenting both its X.509-SVID client certificate and its signed SPIFFE JWT."*

#### 💻 CLI Commands
```bash
source .venv/bin/activate
./run_demo_2.sh
```

#### 🔍 What to Highlight in the Output
* **`✅ Security Verification Passed`**: The manifest passed all semantic policy checks.
* **`🚀 Deployment Executed via Local Container mTLS Agent-to-Agent Link`**:
  * **`Target Container`**: `https://deployer-container:8081` (encrypted TLS 1.3 socket).
  * **`mTLS X.509 SAN`**: `spiffe://aether.internal/ns/devops/sa/release-gate (Verified: True)`.
  * **`Client Cert SHA-256`**: Matches the exact SHA-256 fingerprint of `certs/ops-client.crt`.

---

### 3E. Demo 3: Local Container Obfuscated Manifest Semantic Audit ([`./run_demo_3.sh`](run_demo_3.sh))

#### 🎙️ Presenter Introduction Script
> *"Static regex scanners are easy to bypass by renaming environment variables or Base64-encoding secrets. In Demo 3, we submit [`deployment-obfuscated.yaml`](deployment-obfuscated.yaml), where an attacker hid a Google Cloud API key inside a variable named `SYS_CONN_HASH_VAL_EXT`, Base64-encoded credentials inside `BOOTSTRAP_UPSTREAM_AUTH`, enabled `privileged: true`, and set `hostNetwork: true`."*

#### 💻 CLI Commands
```bash
source .venv/bin/activate
./run_demo_3.sh
```

#### 🔍 What to Highlight in the Output
* **`⚠️ Security Gate Rejected`**: Highlight how Gemini 3.8 semantically reasoned over the manifest—decoding the Base64 Basic Auth string, recognizing the `AIzaSy...` Google API key pattern despite the obfuscated variable name, and flagging `hostNetwork: true`, `privileged: true`, and `/internal/debug-shell`.

---

## Stage 4: Cloud Run Deployment with Agent Identity, Production mTLS Load Balancer & Agent Gateway

### 4A. Build, Push & Deploy to Cloud Run with Agent Identity

#### 🎙️ Presenter Introduction Script
> *"Now we move from local containers to Google Cloud Run. By deploying with `--functional-type=agent` and `--identity-type=agent-identity`, Cloud Run provisions dedicated, cryptographically attested SPIFFE Agent Identity principals (`principal://agents.global.org-...`) instead of legacy service accounts."*

#### 💻 CLI Commands
```bash
PROJECT_ID="your-gcp-project-id"
REGION="us-central1"
REPO_NAME="aether-repo"

# 1. Ensure SPIFFE X.509-SVID certificates and TrustConfig YAMLs are up to date
source .venv/bin/activate
./generate_mtls_certs.py

# 2. Build & push both agent images to Artifact Registry
docker build -t us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/aether-deployer-agent:latest -f Dockerfile.deployer .
docker push us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/aether-deployer-agent:latest

docker build -t us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/aether-ops-agent:latest -f Dockerfile .
docker push us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/aether-ops-agent:latest

# 3. Resolve Cloud Run Agent Identity principals
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")
ORG_ID=$(gcloud projects get-ancestors "${PROJECT_ID}" --format="value(id)" | tail -n 1)
DEPLOYER_AGENT_PRINCIPAL="principal://agents.global.org-${ORG_ID}.system.id.goog/resources/run/projects/${PROJECT_NUMBER}/locations/${REGION}/services/aether-deployer-agent"
OPS_AGENT_PRINCIPAL="principal://agents.global.org-${ORG_ID}.system.id.goog/resources/run/projects/${PROJECT_NUMBER}/locations/${REGION}/services/aether-ops-agent"

# 4. Deploy Downstream Deployer Agent with mTLS Enforcement
gcloud beta run deploy aether-deployer-agent \
  --project="${PROJECT_ID}" \
  --image="us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/aether-deployer-agent:latest" \
  --region="${REGION}" \
  --platform="managed" \
  --functional-type="agent" \
  --identity-type="agent-identity" \
  --allow-unauthenticated \
  --set-env-vars="ENVIRONMENT=production,ENFORCE_SPIFFE_AUTH=true,ENFORCE_MTLS=true" \
  --set-secrets="HMAC_SECRET=aether-hmac-secret:latest"

# 5. Deploy Upstream Ops Agent with mTLS Client Identity
DEPLOYER_URL=$(gcloud beta run services describe aether-deployer-agent \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --format="value(status.url)")

gcloud beta run deploy aether-ops-agent \
  --project="${PROJECT_ID}" \
  --image="us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/aether-ops-agent:latest" \
  --region="${REGION}" \
  --platform="managed" \
  --functional-type="agent" \
  --identity-type="agent-identity" \
  --allow-unauthenticated \
  --set-env-vars="ENVIRONMENT=production,ENFORCE_SPIFFE_AUTH=true,ENFORCE_MTLS=true,PROJECT_ID=${PROJECT_ID},LOCATION=global,GEMINI_MODEL=gemini-3.8-flash,DEPLOYER_AGENT_URL=${DEPLOYER_URL}" \
  --set-secrets="HMAC_SECRET=aether-hmac-secret:latest"
```

---

### 4B. Configure Production Cloud Load Balancer mTLS (`TrustConfig` + `ServerTlsPolicy`)

#### 🎙️ Presenter Introduction Script
> *"In production on Google Cloud Run, we enforce Mutual TLS at Google's edge using a Global External Application Load Balancer backed by Certificate Manager's `TrustConfig` and Network Security's `ServerTlsPolicy` (`clientValidationMode: REJECT_INVALID`). Any connection without a valid X.509 client certificate is dropped at the Google Front End before scaling up a container, and verified connections have their SPIFFE URI SAN (`{client_cert_uri_sans}`) and SHA-256 fingerprint injected into sanitized headers forwarded to Cloud Run."*

#### 💻 CLI Commands
```bash
PROJECT_ID="your-gcp-project-id"
REGION="us-central1"

# 1. Import the SPIFFE Root CA TrustConfig into Certificate Manager
gcloud certificate-manager trust-configs import aether-spiffe-trust-config \
  --project="${PROJECT_ID}" \
  --location="global" \
  --source="certs/trust-config.yaml"

# 2. Import the strict mTLS ServerTlsPolicy (clientValidationMode: REJECT_INVALID)
gcloud network-security server-tls-policies import aether-mtls-server-policy \
  --project="${PROJECT_ID}" \
  --location="global" \
  --source="certs/server-tls-policy.yaml"

# 3. Create Serverless NEG & Backend Service injecting verified mTLS headers
gcloud compute network-endpoint-groups create aether-deployer-neg \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --network-endpoint-type="serverless" \
  --cloud-run-service="aether-deployer-agent"

gcloud compute backend-services create aether-deployer-mtls-backend \
  --project="${PROJECT_ID}" \
  --global \
  --load-balancing-scheme="EXTERNAL_MANAGED" \
  --protocol="HTTPS" \
  --custom-request-header="X-Client-Cert-Present:{client_cert_present}" \
  --custom-request-header="X-Client-Cert-Chain-Verified:{client_cert_chain_verified}" \
  --custom-request-header="X-Client-Cert-Uri-Sans:{client_cert_uri_sans}" \
  --custom-request-header="X-Client-Cert-Sha256-Fingerprint:{client_cert_sha256_fingerprint}"

gcloud compute backend-services add-backend aether-deployer-mtls-backend \
  --project="${PROJECT_ID}" \
  --global \
  --network-endpoint-group="aether-deployer-neg" \
  --network-endpoint-group-region="${REGION}"
```

---

## Stage 5: Live Cloud Run Production, Agent Gateway & mTLS Verification Demos

### 5A. Production Health & Control-Plane Check ([`./test_production_health.sh`](test_production_health.sh))

#### 🎙️ Presenter Introduction Script
> *"Let's verify that both Cloud Run Agent services and our Google Cloud Agent Gateway (`aether-ingress-agw`) are live and healthy in `us-central1`."*

#### 💻 CLI Commands
```bash
source .venv/bin/activate
./test_production_health.sh
```

#### 🔍 What to Highlight in the Output
* **`Ops Agent: ONLINE`** and **`Deployer Agent: ONLINE (SPIFFE Guard Active)`** on their live `*.run.app` endpoints.
* **`Agent Gateway: ONLINE (IAP Request Authz Active)`**, confirming the control-plane gateway resource in `projects/your-gcp-project-id/locations/us-central1/agentGateways/aether-ingress-agw` is active.

---

### 5B. Live Cloud Run Semantic Rejection ([`./test_production_rejection.sh`](test_production_rejection.sh))

#### 🎙️ Presenter Introduction Script
> *"Now we send the obfuscated, vulnerable manifest to our live production Cloud Run Ops Agent, passing our Google OIDC token in `X-Serverless-Authorization` for Cloud Run IAM and our SPIFFE token in `Authorization`."*

#### 💻 CLI Commands
```bash
source .venv/bin/activate
./test_production_rejection.sh
```

#### 🔍 What to Highlight in the Output
* **`=== LIVE PRODUCTION REJECT RESPONSE ===`**: Confirm that the live Cloud Run service invokes Vertex AI (`gemini-3.8-flash`), detects all five obfuscated security violations, and blocks the release gate in production.

---

### 5C. Live Cloud Run Compliant Deployment over Agent Gateway & mTLS ([`./test_production_success.sh`](test_production_success.sh))

#### 🎙️ Presenter Introduction Script
> *"Next, we send our compliant manifest to the live production Cloud Run Ops Agent. The Ops Agent audits the manifest with Gemini 3.8, resolves the downstream Deployer endpoint from Google Cloud Agent Registry, attaches its X.509-SVID mTLS certificate and SPIFFE token, and dispatches the deployment."*

#### 💻 CLI Commands
```bash
source .venv/bin/activate
./test_production_success.sh
```

#### 🔍 What to Highlight in the Output
* **`🚀 Deployment Executed via Secure Agent-to-Agent Link (Agent Gateway + mTLS)`**:
  * **`mTLS X.509 SAN`**: `spiffe://aether.internal/ns/devops/sa/release-gate (Verified: True)`.
  * **`Client Cert SHA-256`**: Displays the verified X.509 client certificate fingerprint.
  * **`Agent Gateway`** & **`Registry Endpoint`**: Shows the exact GCP Agent Gateway resource and Agent Registry endpoint ID used to govern the call.

---

### 5D. Full Control-Plane & Data-Plane Agent Gateway, Registry, IAP & mTLS Suite ([`./test_agent_gateway.sh`](test_agent_gateway.sh))

#### 🎙️ Presenter Introduction Script
> *"Finally, we run our comprehensive 4-stage verification suite. It inspects the live Google Cloud Agent Gateway, the IAP v2 `REQUEST_AUTHZ` policy binding, the Agent Registry endpoint and `roles/iap.egressor` IAM binding for our Ops Agent's `principal://` identity, and executes an end-to-end production deployment over mTLS."*

#### 💻 CLI Commands
```bash
source .venv/bin/activate
./test_agent_gateway.sh
```

#### 🔍 What to Highlight in the Output
* **`[1/4]` Agent Gateway URI & Mode**: `projects/your-gcp-project-id/locations/us-central1/agentGateways/aether-ingress-agw` (`CLIENT_TO_AGENT`).
* **`[2/4]` IAP Request Authz Policy & Extension**: `aether-iap-authz-policy` bound to `aether-iap-authz-ext` (`iap.googleapis.com` v2).
* **`[3/4]` Authorized IAP Egressor**: `principal://agents.global.org-<ORG_ID>.system.id.goog/resources/run/projects/<PROJECT_NUMBER>/locations/us-central1/services/aether-ops-agent`.
* **`[4/4]` `✔ VERIFIED: Traffic discovered via Agent Registry and governed by Agent Gateway!`** along with the verified **mTLS X.509 SAN** (`spiffe://aether.internal/ns/devops/sa/release-gate`).
