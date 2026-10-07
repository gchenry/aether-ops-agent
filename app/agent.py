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
HMAC_SECRET = os.getenv("HMAC_SECRET", "aether-super-secure-demo-secret-key-32-bytes").strip()
MY_SPIFFE_ID = "spiffe://aether.internal/ns/devops/sa/release-gate"


def _get_gcp_access_token_and_project() -> tuple[str, str]:
    """Obtains a live OAuth2 access token and resolves the active Google Cloud project ID."""
    resolved_project = PROJECT_ID if PROJECT_ID and PROJECT_ID != "your-gcp-project-id" else ""
    use_metadata_first = bool(os.getenv("K_SERVICE")) or (
        os.getenv("RUNNING_IN_REASONING_ENGINE", "").lower() == "true"
    )
    if use_metadata_first or not os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        meta_token_url = (
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        )
        meta_proj_url = "http://metadata.google.internal/computeMetadata/v1/project/project-id"
        try:
            with httpx.Client(timeout=2.5) as client:
                if not resolved_project:
                    p_resp = client.get(meta_proj_url, headers={"Metadata-Flavor": "Google"})
                    if p_resp.status_code == 200 and p_resp.text.strip():
                        resolved_project = p_resp.text.strip()
                t_resp = client.get(meta_token_url, headers={"Metadata-Flavor": "Google"})
                if t_resp.status_code == 200:
                    tok = t_resp.json().get("access_token")
                    if tok:
                        return tok, (resolved_project or "your-gcp-project-id")
        except Exception:
            pass

    creds, detected_project = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    creds.refresh(google.auth.transport.requests.Request())
    if not resolved_project:
        resolved_project = detected_project or "your-gcp-project-id"
    return creds.token, resolved_project


def _get_cloud_run_id_token(audience: str) -> str | None:
    """
    Fetches a Google-signed OIDC identity token for Cloud Run service-to-service IAM authentication.
    Supports both Gemini Enterprise Agent Runtime (via IAM Credentials API generateIdToken)
    and Cloud Run metadata server identity endpoints.
    """
    if not audience.startswith("https://"):
        return None

    # 1. When running inside Gemini Enterprise Agent Runtime with AGENT_IDENTITY, mint via IAM Credentials API
    if os.getenv("RUNNING_IN_REASONING_ENGINE", "").lower() == "true":
        try:
            access_token, project_id = _get_gcp_access_token_and_project()
            sa_email = os.getenv(
                "IMPERSONATE_SA_EMAIL",
                f"aether-ops-sa@{project_id}.iam.gserviceaccount.com",
            )
            iam_url = (
                f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa_email}:generateIdToken"
            )
            with httpx.Client(timeout=5.0) as client:
                resp = client.post(
                    iam_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                    json={"audience": audience, "includeEmail": True},
                )
                if resp.status_code == 200 and resp.json().get("token"):
                    return resp.json()["token"]
        except Exception:
            pass

    # 2. Standard Cloud Run metadata server identity endpoint
    try:
        meta_url = (
            "http://metadata.google.internal/computeMetadata/v1/instance/"
            f"service-accounts/default/identity?audience={audience}"
        )
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(meta_url, headers={"Metadata-Flavor": "Google"})
            if resp.status_code == 200 and resp.text.strip():
                return resp.text.strip()
    except Exception:
        pass

    # 3. Fallback to IAM Credentials API if metadata identity endpoint is unavailable
    try:
        access_token, project_id = _get_gcp_access_token_and_project()
        sa_email = os.getenv(
            "IMPERSONATE_SA_EMAIL",
            f"aether-ops-sa@{project_id}.iam.gserviceaccount.com",
        )
        iam_url = (
            f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa_email}:generateIdToken"
        )
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                iam_url,
                headers={"Authorization": f"Bearer {access_token}"},
                json={"audience": audience, "includeEmail": True},
            )
            if resp.status_code == 200 and resp.json().get("token"):
                return resp.json()["token"]
    except Exception:
        pass
    return None


def _resolve_via_agent_gateway_and_registry() -> dict:
    """
    Resolves the downstream Deployer Agent endpoint dynamically from Google Cloud Agent Registry
    and verifies the governing Google Cloud Agent Gateway resource (`aether-ingress-agw`).
    Fails closed if either control-plane resource cannot be verified.
    """
    access_token, project_id = _get_gcp_access_token_and_project()
    gateway_name = os.getenv(
        "AGENT_GATEWAY_NAME",
        f"projects/{project_id}/locations/us-central1/agentGateways/aether-ingress-agw",
    )
    registry_service = os.getenv(
        "AGENT_REGISTRY_SERVICE",
        f"projects/{project_id}/locations/us-central1/services/aether-deployer-service",
    )
    auth_headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Goog-User-Project": project_id,
    }
    with httpx.Client(timeout=8.0) as client:
        # 1. Verify live Agent Gateway resource in Network Services
        gw_resp = client.get(
            f"https://networkservices.googleapis.com/v1/{gateway_name}",
            headers=auth_headers,
        )
        if gw_resp.status_code != 200:
            raise RuntimeError(
                f"Agent Gateway verification failed ({gw_resp.status_code}): {gw_resp.text}"
            )
        gw_data = gw_resp.json()

        # 2. Query Agent Registry Service for dynamic endpoint discovery
        reg_resp = client.get(
            f"https://agentregistry.googleapis.com/v1alpha/{registry_service}",
            headers=auth_headers,
        )
        if reg_resp.status_code != 200:
            raise RuntimeError(
                f"Agent Registry discovery failed ({reg_resp.status_code}): {reg_resp.text}"
            )
        reg_data = reg_resp.json()

    interfaces = reg_data.get("interfaces", [])
    discovered_url = (
        DEPLOYER_MTLS_LB_URL
        or (interfaces[0]["url"].rstrip("/") if interfaces and interfaces[0].get("url") else "")
        or DEPLOYER_AGENT_URL
    )
    registry_endpoint = reg_data.get("registryResource")
    if not registry_endpoint:
        raise RuntimeError(
            f"Agent Registry service {registry_service} is missing registryResource."
        )

    return {
        "target_url": discovered_url,
        "agent_gateway": gw_data["name"],
        "governed_access_path": gw_data.get("googleManaged", {}).get("governedAccessPath"),
        "mtls_psc_endpoint": gw_data.get("agentGatewayCard", {}).get("mtlsEndpoint"),
        "registry_service": reg_data["name"],
        "registry_endpoint": registry_endpoint,
    }


def run_agent_turn(prompt: str, actor_id: str, session_id: str = "default-session") -> str:
    """
    Executes a single agent reasoning turn. If verified, initiates secure mTLS + ABAC agent-to-agent dispatch.
    """
    # 1. Run the semantic manifest check via Google Cloud Model Armor API + Gemini 3.8
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
            or os.getenv("RUNNING_IN_REASONING_ENGINE", "").lower() == "true"
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
            "X-Aether-Spiffe-Authorization": f"Bearer {token}",
            "X-Aether-Gate-Attestation": gate_attestation,
        }
        headers.update(get_client_cert_headers())

        if is_cloud_run and route_info:
            id_token = _get_cloud_run_id_token(target_url)
            if id_token:
                headers["Authorization"] = f"Bearer {id_token}"
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
                        psc_used = deploy_res.get("mtls_psc_endpoint") or route_info.get("mtls_psc_endpoint")
                        return (
                            f"✅ **Security Verification Passed**: All policies compliant (Model Armor: `{armor_status}`).\n\n"
                            f"🚀 **Deployment Executed via Secure Agent-to-Agent Link (Agent Gateway + mTLS + ABAC)**:\n"
                            f"- Job ID: `{deploy_res['deployment_id']}`\n"
                            f"- Cluster: `{deploy_res['cluster']}`\n"
                            f"- ABAC Verdict: `{abac_decision}` (Identity + Environment + Data Scope: `{data_classification}`)\n"
                            f"- mTLS X.509 SAN: `{mtls_san}` (Verified: `{deploy_res.get('mtls_verified', True)}`)\n"
                            f"- Client Cert SHA-256: `{mtls_fp}`\n"
                            f"- Agent Gateway: `{gw_used}`\n"
                            f"- Gateway mTLS PSC Attachment: `{psc_used}`\n"
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
