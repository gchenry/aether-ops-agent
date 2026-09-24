"""
Aether Deployer Agent: Downstream Executor Service (Port 8081).
Enforces zero-trust using SPIFFE Workload Identity validation.
"""

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel
import jwt

# 1. Initialize the FastAPI Application first
app = FastAPI(
    title="Aether Deployer Agent",
    description="Secured downstream deployment execution endpoint."
)

import os

# 2. Configuration Parameters
EXPECTED_CALLER_SPIFFE = "spiffe://aether.internal/ns/devops/sa/release-gate"
HMAC_SECRET = os.getenv("HMAC_SECRET", "aether-super-secure-demo-secret-key-32-bytes").strip()


# 3. Define Pydantic Models for validation
class DeploymentPayload(BaseModel):
    artifact_id: str
    target_cluster: str


# 4. Define HTTP Routes
@app.get("/health", status_code=200)
def health_check():
    return {
        "status": "healthy",
        "service": "aether-deployer-agent",
        "expected_caller": EXPECTED_CALLER_SPIFFE
    }


@app.post("/api/v1/deploy", status_code=status.HTTP_201_CREATED)
def execute_deployment(
    payload: DeploymentPayload,
    authorization: str = Header(None),
    x_goog_agent_gateway: str = Header(None),
    x_goog_agent_registry_endpoint: str = Header(None),
):
    # Enforce SPIFFE identity check on incoming traffic
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access Denied: Missing or malformed authentication header."
        )
        
    token = authorization.split(" ")[1]
    
    try:
        # Decode and verify the SPIFFE token
        decoded = jwt.decode(token, HMAC_SECRET, algorithms=["HS256"])
        spiffe_id = decoded.get("spiffe_id")
        
        print(f"🔒 [Deployer Interceptor] Authenticated SPIFFE ID: {spiffe_id} | Agent Gateway: {x_goog_agent_gateway}")
        
        if spiffe_id != EXPECTED_CALLER_SPIFFE:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Authorization Failed: SPIFFE identity '{spiffe_id}' is not authorized to deploy to this cluster."
            )
            
        return {
            "status": "DEPLOYED",
            "deployment_id": "dep-994821",
            "cluster": payload.target_cluster,
            "agent_gateway": x_goog_agent_gateway or "projects/your-gcp-project-id/locations/us-central1/agentGateways/aether-ingress-agw",
            "registry_endpoint": x_goog_agent_registry_endpoint or "projects/000000000000/locations/us-central1/endpoints/agentregistry-00000000-0000-0000-0000-000000000000",
            "message": f"Successfully deployed {payload.artifact_id}."
        }
        
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Cryptographic identity verification failed: {str(e)}"
        )


# 5. Application Entrypoint
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.deployer:app", host="0.0.0.0", port=8081)
