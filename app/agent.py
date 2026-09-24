"""
Aether Ops Agent: Connected to Downstream Deployer Agent.
"""
import os
import jwt
import httpx
from app.tools import security_scan_manifest

import google.auth
import google.auth.transport.requests

DEPLOYER_AGENT_URL = os.getenv("DEPLOYER_AGENT_URL", "http://localhost:8081")
AGENT_GATEWAY_NAME = os.getenv(
    "AGENT_GATEWAY_NAME",
    "projects/your-gcp-project-id/locations/us-central1/agentGateways/aether-ingress-agw"
)
AGENT_REGISTRY_SERVICE = os.getenv(
    "AGENT_REGISTRY_SERVICE",
    "projects/your-gcp-project-id/locations/us-central1/services/aether-deployer-service"
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
        "target_url": DEPLOYER_AGENT_URL,
        "agent_gateway": AGENT_GATEWAY_NAME,
        "registry_service": AGENT_REGISTRY_SERVICE,
        "registry_endpoint": "projects/000000000000/locations/us-central1/endpoints/agentregistry-00000000-0000-0000-0000-000000000000",
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
                if interfaces and interfaces[0].get("url"):
                    info["target_url"] = interfaces[0]["url"].rstrip("/")
    except Exception:
        pass
    return info

def run_agent_turn(prompt: str, actor_id: str, session_id: str = "default-session") -> str:
    """
    Executes a single agent reasoning turn. If verified, initiates secure agent-to-agent dispatch.
    """
    # 1. Run the semantic manifest check via our AI-powered tool (Gemini)
    scan_res = security_scan_manifest(prompt)
    
    # 2. If Gemini auditor finds a policy violation, format and return them
    if scan_res.get("status") == "FAILED":
        violations = "\n".join([f"- {finding}" for finding in scan_res.get("findings", [])])
        return (
            f"⚠️ **Security Gate Rejected**: Vulnerabilities detected in manifest:\n"
            f"{violations}\n\n"
            f"**Action Required**: Please resolve these security architectural flaws before attempting deployment."
        )

    # 3. If prompt asks to deploy and security passed, execute the secure handoff
    if "deploy" in prompt.lower():
        is_cloud_run = DEPLOYER_AGENT_URL.startswith("https://")
        if is_cloud_run:
            route_info = _resolve_via_agent_gateway_and_registry()
            target_url = route_info["target_url"]
        else:
            route_info = None
            target_url = DEPLOYER_AGENT_URL

        # Sign SPIFFE workload token for Agent-to-Agent Communication
        token = jwt.encode(
            {"spiffe_id": MY_SPIFFE_ID, "role": "admin"},
            HMAC_SECRET,
            algorithm="HS256"
        )

        headers = {"Authorization": f"Bearer {token}"}
        if is_cloud_run and route_info:
            headers["X-Goog-Agent-Gateway"] = route_info["agent_gateway"]
            headers["X-Goog-Agent-Registry-Endpoint"] = route_info["registry_endpoint"]
            id_token = _get_cloud_run_id_token(target_url)
            if id_token:
                headers["X-Serverless-Authorization"] = f"Bearer {id_token}"

        payload = {
            "artifact_id": "gcr.io/aether/agent:v2.4",
            "target_cluster": "us-central1-prod"
        }

        try:
            with httpx.Client(timeout=15.0) as client:
                res = httpx.post(f"{target_url}/api/v1/deploy", json=payload, headers=headers)
                
                if res.status_code == 201:
                    deploy_res = res.json()
                    if is_cloud_run and route_info:
                        gw_used = deploy_res.get("agent_gateway") or route_info["agent_gateway"]
                        ep_used = deploy_res.get("registry_endpoint") or route_info["registry_endpoint"]
                        return (
                            f"✅ **Security Verification Passed**: All policies compliant.\n\n"
                            f"🚀 **Deployment Executed via Secure Agent-to-Agent Link (Agent Gateway)**:\n"
                            f"- Job ID: `{deploy_res['deployment_id']}`\n"
                            f"- Cluster: `{deploy_res['cluster']}`\n"
                            f"- Agent Gateway: `{gw_used}`\n"
                            f"- Registry Endpoint: `{ep_used}`\n"
                            f"- Message: {deploy_res['message']}"
                        )
                    return (
                        f"✅ **Security Verification Passed**: All policies compliant.\n\n"
                        f"🚀 **Deployment Executed via Local Container Agent-to-Agent Link**:\n"
                        f"- Job ID: `{deploy_res['deployment_id']}`\n"
                        f"- Cluster: `{deploy_res['cluster']}`\n"
                        f"- Target Container: `{target_url}`\n"
                        f"- Message: {deploy_res['message']}"
                    )
                else:
                    return f"❌ Downstream Deployer rejected request: {res.text}"
                    
        except httpx.RequestError as e:
            return f"❌ Connection to Downstream Deployer Agent failed: {str(e)}"

    return (
        f"✅ **Security Verification Passed**: All policies compliant.\n\n"
        f"Manifest is clean and ready for deployment."
    )
