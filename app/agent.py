"""
Aether Ops Agent: Connected to Downstream Deployer Agent.
"""
import os
import jwt
import httpx
from app.tools import security_scan_manifest

# Target downstream agent
DEPLOYER_AGENT_URL = os.getenv("DEPLOYER_AGENT_URL", "http://localhost:8081")
HMAC_SECRET = "aether-super-secure-demo-secret-key-32-bytes"
MY_SPIFFE_ID = "spiffe://aether.internal/ns/devops/sa/release-gate"

def run_agent_turn(prompt: str, actor_id: str, session_id: str = "default-session") -> str:
    """
    Executes a single agent reasoning turn. If verified, initiates secure agent-to-agent dispatch.
    """
    scan_res = security_scan_manifest(prompt)
    if scan_res["status"] == "FAILED":
        return (
            f"⚠️ **Security Gate Rejected**: Vulnerabilities detected in manifest:\n"
            f"- {scan_res['findings'][0]}\n\n"
            f"**Action Required**: Remove hardcoded credentials and utilize Secret Manager before deploying."
        )
    
    elif "deploy" in prompt.lower():
        # Sign SPIFFE workload token for Agent-to-Agent Communication
        token = jwt.encode(
            {"spiffe_id": MY_SPIFFE_ID, "role": "admin"},
            HMAC_SECRET,
            algorithm="HS256"
        )

        # Call Downstream Deployer Agent
        headers = {"Authorization": f"Bearer {token}"}
        payload = {
            "artifact_id": "gcr.io/aether/agent:v2.4",
            "target_cluster": "us-central1-prod"
        }

        try:
            with httpx.Client() as client:
                res = client.post(f"{DEPLOYER_AGENT_URL}/api/v1/deploy", json=payload, headers=headers)
                
                if res.status_code == 201:
                    deploy_res = res.json()
                    return (
                        f"✅ **Security Verification Passed**: All policies compliant.\n\n"
                        f"🚀 **Deployment Executed via Secure Agent-to-Agent Link**:\n"
                        f"- Job ID: `{deploy_res['deployment_id']}`\n"
                        f"- Cluster: `{deploy_res['cluster']}`\n"
                        f"- Message: {deploy_res['message']}"
                    )
                else:
                    return f"❌ Downstream Deployer rejected request: {res.text}"
                    
        except httpx.RequestError as e:
            return f"❌ Connection to Downstream Deployer Agent failed: {str(e)}"

    return "Aether Ops ready. Please provide a manifest to scan or specify a deployment command."
