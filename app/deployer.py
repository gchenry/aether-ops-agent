"""
Aether Deployer Agent: Downstream Executor Service (Port 8081).
Enforces zero-trust using SPIFFE Workload Identity validation.
"""
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel
import jwt

app = FastAPI(
    title="Aether Deployer Agent",
    description="Secured downstream deployment execution endpoint."
)

# Config
EXPECTED_CALLER_SPIFFE = "spiffe://aether.internal/ns/devops/sa/release-gate"
HMAC_SECRET = "aether-super-secure-demo-secret-key-32-bytes"

class DeploymentPayload(BaseModel):
    artifact_id: str
    target_cluster: str

@app.post("/api/v1/deploy", status_code=status.HTTP_201_CREATED)
def execute_deployment(
    payload: DeploymentPayload,
    authorization: str = Header(None)
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

        print(f"🔒 [Deployer Interceptor] Authenticated SPIFFE ID: {spiffe_id}")

        if spiffe_id != EXPECTED_CALLER_SPIFFE:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Authorization Failed: SPIFFE identity '{spiffe_id}' is not authorized to deploy to this cluster."
            )

        return {
            "status": "DEPLOYED",
            "deployment_id": "dep-994821",
            "cluster": payload.target_cluster,
            "message": f"Successfully deployed {payload.artifact_id}."
        }

    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Cryptographic identity verification failed: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.deployer:app", host="0.0.0.0", port=8081)
