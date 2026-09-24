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
import jwt

client = TestClient(app)
HMAC_SECRET = "aether-super-secure-demo-secret-key-32-bytes"

def test_health_endpoint_public():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

def test_unauthorized_request_rejected():
    res = client.post("/api/v1/agent/invoke", json={"prompt": "Deploy app"})
    assert res.status_code == 401

def test_authorized_spiffe_request():
    token = jwt.encode(
        {"spiffe_id": "spiffe://aether.internal/ns/devops/sa/release-gate", "role": "admin"},
        HMAC_SECRET,
        algorithm="HS256"
    )
    headers = {"Authorization": f"Bearer {token}"}
    res = client.post("/api/v1/agent/invoke", json={"prompt": "Deploy my container"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["actor_spiffe_id"] == "spiffe://aether.internal/ns/devops/sa/release-gate"

if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v", "-s"]))

