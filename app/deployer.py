"""
Aether Deployer Agent: Downstream Executor Service (Port 8081).
Enforces zero-trust using Mutual TLS (mTLS X.509-SVID + Cloud Load Balancer ServerTlsPolicy)
and SPIFFE Workload Identity JWT validation.
"""

import os
import ssl
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel
import httpx
import jwt
import google.auth
import google.auth.transport.requests
from app.mtls import ensure_mtls_certificates, verify_mtls_client_identity
from app.abac import evaluate_abac_policy

# 1. Initialize the FastAPI Application first
app = FastAPI(
    title="Aether Deployer Agent",
    description="Secured downstream deployment execution endpoint with Mutual TLS (mTLS) and ABAC."
)

# 2. Configuration Parameters
EXPECTED_CALLER_SPIFFE = "spiffe://aether.internal/ns/devops/sa/release-gate"
HMAC_SECRET = os.getenv("HMAC_SECRET", "aether-super-secure-demo-secret-key-32-bytes").strip()
ENFORCE_MTLS = os.getenv("ENFORCE_MTLS", "true").lower() == "true"

_cached_control_plane_info: dict | None = None


def _verify_live_gateway_and_registry() -> dict:
    """
    Queries the live Google Cloud Network Services (AgentGateway) and Agent Registry APIs
    when running in Cloud Run to verify control-plane governance without synthetic headers or mock fallbacks.
    """
    global _cached_control_plane_info
    if not os.getenv("K_SERVICE"):
        return {
            "agent_gateway": None,
            "registry_endpoint": None,
            "mtls_psc_endpoint": None,
            "governed_access_path": None,
        }
    if _cached_control_plane_info is not None:
        return _cached_control_plane_info

    access_token: str | None = None
    detected_project: str | None = None
    try:
        with httpx.Client(timeout=2.5) as meta_client:
            t_resp = meta_client.get(
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                headers={"Metadata-Flavor": "Google"},
            )
            if t_resp.status_code == 200:
                access_token = t_resp.json().get("access_token")
            p_resp = meta_client.get(
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                headers={"Metadata-Flavor": "Google"},
            )
            if p_resp.status_code == 200 and p_resp.text.strip():
                detected_project = p_resp.text.strip()
    except Exception:
        pass

    if not access_token:
        creds, adc_project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        creds.refresh(google.auth.transport.requests.Request())
        access_token = creds.token
        detected_project = detected_project or adc_project

    env_project = os.getenv("PROJECT_ID", "")
    project_id = (
        env_project
        if env_project and env_project != "your-gcp-project-id"
        else (detected_project or "your-gcp-project-id")
    )
    sa_email = os.getenv(
        "IMPERSONATE_SA_EMAIL",
        f"aether-ops-sa@{project_id}.iam.gserviceaccount.com",
    )
    try:
        with httpx.Client(timeout=5.0) as iam_client:
            iam_resp = iam_client.post(
                f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa_email}:generateAccessToken",
                headers={"Authorization": f"Bearer {access_token}"},
                json={"scope": ["https://www.googleapis.com/auth/cloud-platform"]},
            )
            if iam_resp.status_code == 200 and iam_resp.json().get("accessToken"):
                access_token = iam_resp.json()["accessToken"]
    except Exception:
        pass

    location = "us-central1"
    gateway_name = os.getenv(
        "AGENT_GATEWAY_NAME",
        f"projects/{project_id}/locations/{location}/agentGateways/aether-ingress-agw",
    )
    registry_service = os.getenv(
        "AGENT_REGISTRY_SERVICE",
        f"projects/{project_id}/locations/{location}/services/aether-deployer-service",
    )
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Goog-User-Project": project_id,
    }
    with httpx.Client(timeout=8.0) as client:
        gw_resp = client.get(
            f"https://networkservices.googleapis.com/v1/{gateway_name}",
            headers=headers,
        )
        if gw_resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to verify Agent Gateway {gateway_name}: {gw_resp.text}",
            )
        gw_data = gw_resp.json()

        reg_resp = client.get(
            f"https://agentregistry.googleapis.com/v1alpha/{registry_service}",
            headers=headers,
        )
        if reg_resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to verify Agent Registry service {registry_service}: {reg_resp.text}",
            )
        reg_data = reg_resp.json()

    _cached_control_plane_info = {
        "agent_gateway": gw_data["name"],
        "registry_endpoint": reg_data["registryResource"],
        "mtls_psc_endpoint": gw_data.get("agentGatewayCard", {}).get("mtlsEndpoint"),
        "governed_access_path": gw_data.get("googleManaged", {}).get("governedAccessPath"),
    }
    return _cached_control_plane_info


# 3. Define Pydantic Models for validation
class DeploymentPayload(BaseModel):
    artifact_id: str
    target_cluster: str
    environment: str = "production"
    tenant_id: str = "tenant-aether-core"
    data_classification: str = "production-release"
    action_severity: str = "standard"
    swarm_hop_count: int = 1
    model_armor_status: str = "CLEAN"


# 4. Define HTTP Routes
@app.get("/health", status_code=200)
def health_check():
    return {
        "status": "healthy",
        "service": "aether-deployer-agent",
        "expected_caller": EXPECTED_CALLER_SPIFFE,
        "mtls_enforced": ENFORCE_MTLS,
        "abac_enforced": True,
        "framework": "3Cs (Contain, Curate, Control)",
        "trust_domain": "spiffe://aether.internal",
    }


@app.post("/api/v1/deploy", status_code=status.HTTP_201_CREATED)
def execute_deployment(
    payload: DeploymentPayload,
    authorization: str = Header(None),
    x_aether_spiffe_authorization: str = Header(None),
    x_aether_gate_attestation: str = Header(None),
    x_aether_hitl_token: str = Header(None),
    x_client_cert_present: str = Header(None),
    x_client_cert_chain_verified: str = Header(None),
    x_client_cert_uri_sans: str = Header(None),
    x_client_cert_sha256_fingerprint: str = Header(None),
    x_client_cert_pem_b64: str = Header(None),
):
    # 1. Enforce SPIFFE Non-Human Identity (NHI) JWT check on incoming traffic (CONTAIN)
    spiffe_hdr = (
        x_aether_spiffe_authorization
        if isinstance(x_aether_spiffe_authorization, str)
        else None
    )
    std_hdr = authorization if isinstance(authorization, str) else None
    auth_header = spiffe_hdr or std_hdr
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access Denied: Missing or malformed authentication header."
        )
        
    token = auth_header.split(" ")[1]
    
    try:
        # Decode and verify the SPIFFE token
        decoded = jwt.decode(token, HMAC_SECRET, algorithms=["HS256"])
        spiffe_id = decoded.get("spiffe_id")
        role = decoded.get("role", "admin")
        
        if spiffe_id != EXPECTED_CALLER_SPIFFE:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"[OWASP ASI02/ASI03: Tool Misuse & Shadow AI Blocked] Authorization Failed: "
                    f"Non-Human Identity '{spiffe_id}' is not authorized to deploy to this cluster."
                )
            )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Cryptographic identity verification failed: {str(e)}"
        )

    # 2. Enforce Mutual TLS (mTLS) X.509-SVID & Cloud Load Balancer ServerTlsPolicy verification (CONTAIN — ASI07)
    mtls_info = {
        "mtls_verified": False,
        "verification_mode": "DISABLED",
        "client_cert_uri_san": None,
        "client_cert_fingerprint": None,
    }
    if ENFORCE_MTLS:
        mtls_info = verify_mtls_client_identity(
            expected_spiffe_id=EXPECTED_CALLER_SPIFFE,
            x_client_cert_present=x_client_cert_present,
            x_client_cert_chain_verified=x_client_cert_chain_verified,
            x_client_cert_uri_sans=x_client_cert_uri_sans,
            x_client_cert_sha256_fingerprint=x_client_cert_sha256_fingerprint,
            x_client_cert_pem_b64=x_client_cert_pem_b64,
        )

    # 3. Enforce 3Cs (Contain, Curate, Control) & Attribute-Based Access Control (ABAC)
    abac_res = evaluate_abac_policy(
        spiffe_id=spiffe_id,
        role=role,
        mtls_verified=mtls_info["mtls_verified"],
        client_cert_uri_san=mtls_info["client_cert_uri_san"],
        environment=payload.environment,
        target_cluster=payload.target_cluster,
        artifact_id=payload.artifact_id,
        data_classification=payload.data_classification,
        model_armor_status=payload.model_armor_status,
        gate_attestation=x_aether_gate_attestation,
        tenant_id=payload.tenant_id,
        action_severity=payload.action_severity,
        swarm_hop_count=payload.swarm_hop_count,
        hitl_approval_token=x_aether_hitl_token,
    )

    cp_info = _verify_live_gateway_and_registry()

    print(
        f"🔒 [Deployer Interceptor] Authenticated SPIFFE ID: {spiffe_id} | "
        f"mTLS Verified: {mtls_info['mtls_verified']} ({mtls_info['verification_mode']}) | "
        f"ABAC Decision: {abac_res['decision']} | "
        f"Cert FP: {mtls_info['client_cert_fingerprint']} | "
        f"Agent Gateway: {cp_info['agent_gateway']}"
    )

    return {
        "status": "DEPLOYED",
        "deployment_id": "dep-994821",
        "cluster": payload.target_cluster,
        "mtls_verified": mtls_info["mtls_verified"],
        "mtls_verification_mode": mtls_info["verification_mode"],
        "client_cert_uri_san": mtls_info["client_cert_uri_san"],
        "client_cert_fingerprint": mtls_info["client_cert_fingerprint"],
        "abac_decision": abac_res["decision"],
        "abac_policy_id": abac_res["policy_id"],
        "abac_attributes": abac_res["attributes_verified"],
        "agent_gateway": cp_info["agent_gateway"],
        "registry_endpoint": cp_info["registry_endpoint"],
        "mtls_psc_endpoint": cp_info["mtls_psc_endpoint"],
        "governed_access_path": cp_info["governed_access_path"],
        "message": f"Successfully deployed {payload.artifact_id}."
    }


# 5. Application Entrypoint
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8081"))
    enable_socket_mtls = os.getenv("ENABLE_SOCKET_MTLS", "false").lower() == "true"
    if enable_socket_mtls:
        cert_paths = ensure_mtls_certificates()
        uvicorn.run(
            "app.deployer:app",
            host="0.0.0.0",
            port=port,
            ssl_keyfile=str(cert_paths["server_key"]),
            ssl_certfile=str(cert_paths["server_cert"]),
            ssl_ca_certs=str(cert_paths["ca_cert"]),
            ssl_cert_reqs=ssl.CERT_REQUIRED,
        )
    else:
        uvicorn.run("app.deployer:app", host="0.0.0.0", port=port)
