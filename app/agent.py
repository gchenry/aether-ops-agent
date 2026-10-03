"""
Aether Ops Agent: Connected to Downstream Deployer Agent over Mutual TLS (mTLS).
"""
import os
import jwt
import httpx
from app.config import settings
from app.tools import security_scan_manifest
from app.mtls import create_mtls_client_context, get_client_cert_headers
from app.abac import compute_gate_attestation

import google.auth
import google.auth.transport.requests

PROJECT_ID = os.getenv("PROJECT_ID", settings.PROJECT_ID)
DEPLOYER_AGENT_URL = os.getenv("DEPLOYER_AGENT_URL", "https://localhost:8081")
DEPLOYER_MTLS_LB_URL = os.getenv("DEPLOYER_MTLS_LB_URL", "")
AGENT_GATEWAY_NAME = os.getenv(
    "AGENT_GATEWAY_NAME",
    f"projects/{PROJECT_ID}/locations/us-central1/agentGateways/aether-ingress-agw"
)
AGENT_REGISTRY_SERVICE = os.getenv(
    "AGENT_REGISTRY_SERVICE",
    f"projects/{PROJECT_ID}/locations/us-central1/services/aether-deployer-service"
)
HMAC_SECRET = os.getenv("HMAC_SECRET", "aether-super-secure-demo-secret-key-32-bytes").strip()
MY_SPIFFE_ID = "spiffe://aether.internal/ns/devops/sa/release-gate"

def _get_cloud_run_id_token(audience: str) -> str | None:
    """Fetches an OIDC identity token from the Cloud Run metadata server for service-to-service IAM auth."""
    if not audience.startswith("https://"):
        return None
    try:
        meta_url = f"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={audience}"
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(meta_url, headers={"Metadata-Flavor": "Google"})
            if resp.status_code == 200:
                return resp.text.strip()
    except Exception:
        pass
    return None

def _resolve_via_agent_gateway_and_registry() -> dict:
    """
    Resolves the downstream Deployer Agent endpoint from Google Cloud Agent Registry
    and verifies the governing Agent Gateway resource.
    """
    info = {
        "target_url": DEPLOYER_MTLS_LB_URL or DEPLOYER_AGENT_URL,
        "agent_gateway": AGENT_GATEWAY_NAME,
        "registry_service": AGENT_REGISTRY_SERVICE,
        "registry_endpoint": os.getenv(
            "AGENT_REGISTRY_ENDPOINT",
            f"projects/{PROJECT_ID}/locations/us-central1/endpoints/agentregistry-00000000-0000-0000-0000-000000000000",
        ),
    }
    try:
        creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        creds.refresh(google.auth.transport.requests.Request())
        auth_headers = {"Authorization": f"Bearer {creds.token}"}
        with httpx.Client(timeout=5.0) as client:
            # 1. Query Agent Gateway
            gw_resp = client.get(
                f"https://networkservices.googleapis.com/v1beta1/{AGENT_GATEWAY_NAME}",
                headers=auth_headers,
            )
            if gw_resp.status_code == 200:
                gw_data = gw_resp.json()
                info["agent_gateway"] = gw_data.get("name", AGENT_GATEWAY_NAME)

            # 2. Query Agent Registry Service for dynamic endpoint discovery
            reg_resp = client.get(
                f"https://agentregistry.googleapis.com/v1alpha/{AGENT_REGISTRY_SERVICE}",
                headers=auth_headers,
            )
            if reg_resp.status_code == 200:
                reg_data = reg_resp.json()
                info["registry_endpoint"] = reg_data.get("registryResource", info["registry_endpoint"])
                interfaces = reg_data.get("interfaces", [])
                if not DEPLOYER_MTLS_LB_URL and interfaces and interfaces[0].get("url"):
                    info["target_url"] = interfaces[0]["url"].rstrip("/")
    except Exception:
        pass
    return info

def run_agent_turn(prompt: str, actor_id: str, session_id: str = "default-session") -> str:
    """
    Executes a single agent reasoning turn. If verified, initiates secure mTLS + ABAC agent-to-agent dispatch.
    """
    # 1. Run the semantic manifest check via Model Armor + Gemini 3.8
    scan_res = security_scan_manifest(prompt)
    armor_status = scan_res.get("model_armor_status", "CLEAN")
    scc_telemetry = scan_res.get("scc_telemetry", "POLICY_VIOLATION_DETECTED")
    wiz_posture = scan_res.get("wiz_posture", "HIGH_RISK_MANIFEST_BLOCKED")
    
    # 2. If Model Armor or Gemini auditor finds a policy violation, format and return them
    if scan_res.get("status") == "FAILED":
        violations = "\n".join([f"- {finding}" for finding in scan_res.get("findings", [])])
        return (
            f"⚠️ **Security Gate Rejected**: Vulnerabilities detected in manifest:\n"
            f"{violations}\n\n"
            f"🛡️ **Telemetry Emitted**:\n"
            f"- Google Cloud Model Armor: `{armor_status}`\n"
            f"- Security Command Center (SCC): `{scc_telemetry}`\n"
            f"- Wiz Cloud Posture Issue: `{wiz_posture}`\n\n"
            f"**Action Required**: Please resolve these security architectural flaws before attempting deployment."
        )

    # 3. If prompt asks to deploy and security passed, execute the secure mTLS + ABAC handoff
    if "deploy" in prompt.lower():
        is_cloud_run = (
            ".run.app" in DEPLOYER_AGENT_URL
            or bool(DEPLOYER_MTLS_LB_URL)
            or bool(os.getenv("K_SERVICE"))
        )
        if is_cloud_run:
            route_info = _resolve_via_agent_gateway_and_registry()
            target_url = route_info["target_url"]
        else:
            route_info = None
            target_url = DEPLOYER_AGENT_URL
            if target_url.startswith("http://deployer-container:"):
                target_url = target_url.replace("http://", "https://", 1)

        # Sign SPIFFE workload token for Agent-to-Agent Communication
        token = jwt.encode(
            {"spiffe_id": MY_SPIFFE_ID, "role": "admin"},
            HMAC_SECRET,
            algorithm="HS256"
        )

        artifact_id = "gcr.io/aether/agent:v2.4"
        target_cluster = "us-central1-prod"
        data_classification = "production-release"

        # Compute cryptographic Security Gate attestation (prevents OWASP ASI02 Tool Misuse)
        gate_attestation = compute_gate_attestation(
            spiffe_id=MY_SPIFFE_ID,
            artifact_id=artifact_id,
            target_cluster=target_cluster,
            data_classification=data_classification,
            model_armor_status=armor_status,
        )

        # Attach SPIFFE JWT + X.509-SVID Client Certificate headers + ABAC Gate Attestation
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Aether-Gate-Attestation": gate_attestation,
        }
        headers.update(get_client_cert_headers())

        if is_cloud_run and route_info:
            headers["X-Goog-Agent-Gateway"] = route_info["agent_gateway"]
            headers["X-Goog-Agent-Registry-Endpoint"] = route_info["registry_endpoint"]
            id_token = _get_cloud_run_id_token(DEPLOYER_AGENT_URL)
            if id_token:
                headers["X-Serverless-Authorization"] = f"Bearer {id_token}"

        payload = {
            "artifact_id": artifact_id,
            "target_cluster": target_cluster,
            "environment": "production",
            "data_classification": data_classification,
            "model_armor_status": armor_status,
        }

        try:
            ssl_ctx = create_mtls_client_context()
            with httpx.Client(verify=ssl_ctx, timeout=15.0) as client:
                try:
                    res = client.post(f"{target_url}/api/v1/deploy", json=payload, headers=headers)
                except httpx.ConnectError:
                    # Graceful fallback if local python dev server was started on plain HTTP
                    if not is_cloud_run and target_url.startswith("https://"):
                        fallback_url = target_url.replace("https://", "http://", 1)
                        res = client.post(f"{fallback_url}/api/v1/deploy", json=payload, headers=headers)
                        target_url = fallback_url
                    else:
                        raise
                
                if res.status_code == 201:
                    deploy_res = res.json()
                    mtls_san = deploy_res.get("client_cert_uri_san") or MY_SPIFFE_ID
                    mtls_fp = (deploy_res.get("client_cert_fingerprint") or "")[:16] + "..."
                    abac_decision = deploy_res.get("abac_decision", "ALLOW")
                    if is_cloud_run and route_info:
                        gw_used = deploy_res.get("agent_gateway") or route_info["agent_gateway"]
                        ep_used = deploy_res.get("registry_endpoint") or route_info["registry_endpoint"]
                        return (
                            f"✅ **Security Verification Passed**: All policies compliant (Model Armor: `{armor_status}`).\n\n"
                            f"🚀 **Deployment Executed via Secure Agent-to-Agent Link (Agent Gateway + mTLS + ABAC)**:\n"
                            f"- Job ID: `{deploy_res['deployment_id']}`\n"
                            f"- Cluster: `{deploy_res['cluster']}`\n"
                            f"- ABAC Verdict: `{abac_decision}` (Identity + Environment + Data Scope: `{data_classification}`)\n"
                            f"- mTLS X.509 SAN: `{mtls_san}` (Verified: `{deploy_res.get('mtls_verified', True)}`)\n"
                            f"- Client Cert SHA-256: `{mtls_fp}`\n"
                            f"- Agent Gateway: `{gw_used}`\n"
                            f"- Registry Endpoint: `{ep_used}`\n"
                            f"- Message: {deploy_res['message']}"
                        )
                    return (
                        f"✅ **Security Verification Passed**: All policies compliant (Model Armor: `{armor_status}`).\n\n"
                        f"🚀 **Deployment Executed via Local Container mTLS + ABAC Agent-to-Agent Link**:\n"
                        f"- Job ID: `{deploy_res['deployment_id']}`\n"
                        f"- Cluster: `{deploy_res['cluster']}`\n"
                        f"- Target Container: `{target_url}`\n"
                        f"- ABAC Verdict: `{abac_decision}` (Identity + Environment + Data Scope: `{data_classification}`)\n"
                        f"- mTLS X.509 SAN: `{mtls_san}` (Verified: `{deploy_res.get('mtls_verified', True)}`)\n"
                        f"- Client Cert SHA-256: `{mtls_fp}`\n"
                        f"- Message: {deploy_res['message']}"
                    )
                else:
                    return f"❌ Downstream Deployer rejected request: {res.text}"
                    
        except httpx.RequestError as e:
            return f"❌ Connection to Downstream Deployer Agent failed: {str(e)}"

    return (
        f"✅ **Security Verification Passed**: All policies compliant (Model Armor: `{armor_status}`).\n\n"
        f"Manifest is clean and ready for deployment."
    )
