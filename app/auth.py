"""
Enterprise Identity & SPIFFE Token Verification Interceptor
Prevents Broken Object Level Authorization (BOLA) and rogue agent impersonation.
"""
from fastapi import Header, HTTPException, status
import os
import jwt
from app.config import settings

HMAC_SECRET = os.getenv("HMAC_SECRET", "aether-super-secure-demo-secret-key-32-bytes").strip()


def verify_agent_identity(
    authorization: str = Header(None),
    x_aether_spiffe_authorization: str = Header(None),
) -> dict:
    """
    Validates SPIFFE Workload Identity / Bearer JWT tokens passed during inter-agent calls.
    Enforces cryptographic signature verification (HS256) and SPIFFE ID authorization.
    """
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
            detail="Missing or malformed Authorization header with Bearer token."
        )

    token = auth_header.split(" ")[1]

    try:
        decoded = jwt.decode(token, HMAC_SECRET, algorithms=["HS256"])

        spiffe_id = decoded.get("spiffe_id") or decoded.get("sub")
        role = decoded.get("role", "viewer")

        if spiffe_id != settings.EXPECTED_SPIFFE_ID and role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: SPIFFE ID '{spiffe_id}' is not authorized for deployment release gates."
            )

        return decoded

    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid agent authentication token: {str(e)}"
        )

