#!/usr/bin/env python3
"""
Tests SPIFFE interceptor enforcement.
"""
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_VENV_DIR = os.path.join(_ROOT, ".venv")
_VENV_PY = os.path.join(_VENV_DIR, "bin", "python")
if os.path.exists(_VENV_PY) and os.path.abspath(sys.prefix) != os.path.abspath(_VENV_DIR):
    os.execv(_VENV_PY, [_VENV_PY, *sys.argv])
sys.path.insert(0, _ROOT)

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.deployer import app as deployer_app
from app.mtls import ensure_mtls_certificates, get_client_cert_headers
import jwt

client = TestClient(app)
deployer_client = TestClient(deployer_app)
HMAC_SECRET = "aether-super-secure-demo-secret-key-32-bytes"

def _make_spiffe_jwt(spiffe_id: str = "spiffe://aether.internal/ns/devops/sa/release-gate") -> str:
    return jwt.encode(
        {"spiffe_id": spiffe_id, "role": "admin"},
        HMAC_SECRET,
        algorithm="HS256"
    )

def test_health_endpoint_public():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

def test_unauthorized_request_rejected():
    res = client.post("/api/v1/agent/invoke", json={"prompt": "Deploy app"})
    assert res.status_code == 401

def test_authorized_spiffe_request():
    token = _make_spiffe_jwt()
    headers = {"Authorization": f"Bearer {token}"}
    res = client.post("/api/v1/agent/invoke", json={"prompt": "Check manifest status"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["actor_spiffe_id"] == "spiffe://aether.internal/ns/devops/sa/release-gate"

def test_mtls_missing_client_cert_rejected():
    """Deployer rejects requests that present a valid JWT but lack mTLS client cert / LB headers."""
    token = _make_spiffe_jwt()
    headers = {"Authorization": f"Bearer {token}"}
    res = deployer_client.post(
        "/api/v1/deploy",
        json={"artifact_id": "gcr.io/aether/agent:v2.4", "target_cluster": "us-central1-prod"},
        headers=headers,
    )
    assert res.status_code == 401
    assert "mTLS Verification Failed" in res.json()["detail"]

def test_mtls_unverified_lb_chain_rejected():
    """Deployer rejects requests when Cloud Load Balancer reports client cert chain is unverified."""
    token = _make_spiffe_jwt()
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Client-Cert-Present": "true",
        "X-Client-Cert-Chain-Verified": "false",
        "X-Client-Cert-Uri-Sans": "spiffe://aether.internal/ns/devops/sa/release-gate",
    }
    res = deployer_client.post(
        "/api/v1/deploy",
        json={"artifact_id": "gcr.io/aether/agent:v2.4", "target_cluster": "us-central1-prod"},
        headers=headers,
    )
    assert res.status_code == 401

def test_mtls_unauthorized_uri_san_rejected():
    """Deployer rejects requests when Cloud Load Balancer reports an unauthorized X.509 SAN URI."""
    token = _make_spiffe_jwt()
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Client-Cert-Present": "true",
        "X-Client-Cert-Chain-Verified": "true",
        "X-Client-Cert-Uri-Sans": "spiffe://aether.internal/ns/rogue/sa/intruder",
    }
    res = deployer_client.post(
        "/api/v1/deploy",
        json={"artifact_id": "gcr.io/aether/agent:v2.4", "target_cluster": "us-central1-prod"},
        headers=headers,
    )
    assert res.status_code == 403

def test_mtls_valid_x509_svid_and_lb_headers_accepted():
    """Deployer accepts requests with a cryptographically valid X.509-SVID client certificate."""
    ensure_mtls_certificates()
    token = _make_spiffe_jwt()
    headers = {"Authorization": f"Bearer {token}"}
    headers.update(get_client_cert_headers())
    res = deployer_client.post(
        "/api/v1/deploy",
        json={"artifact_id": "gcr.io/aether/agent:v2.4", "target_cluster": "us-central1-prod"},
        headers=headers,
    )
    assert res.status_code == 201
    body = res.json()
    assert body["mtls_verified"] is True
    assert body["client_cert_uri_san"] == "spiffe://aether.internal/ns/devops/sa/release-gate"

if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v", "-s"]))


