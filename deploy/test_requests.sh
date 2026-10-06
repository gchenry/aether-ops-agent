#!/usr/bin/env bash
# Live "Lesson Stick" Demo Script

SERVICE_URL=${1:-"http://localhost:8080"}

echo "=== 1. Testing Unauthenticated Request (Simulated Attacker) ==="
curl -s -X POST "${SERVICE_URL}/api/v1/agent/invoke" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Deploy unapproved image to cluster"}' | python3 -m json.tool

echo -e "\n=== 2. Testing Authenticated SPIFFE Identity (Valid DevSecOps Agent) ==="
# Generate valid token
VALID_TOKEN=$(python3 -c "import jwt; print(jwt.encode({'spiffe_id': 'spiffe://aether.internal/ns/devops/sa/release-gate', 'role': 'admin'}, 'aether-super-secure-demo-secret-key-32-bytes', algorithm='HS256'))")

curl -s -X POST "${SERVICE_URL}/api/v1/agent/invoke" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${VALID_TOKEN}" \
  -d '{"prompt": "Deploy verified container gcr.io/aether/app:v1"}' | python3 -m json.tool

