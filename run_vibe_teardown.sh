#!/usr/bin/env bash
# SF Tech Week 2026 Masterclass Live Demo:
# "Vibe Coding Hangover: Securing Agentic AI with Zero-Trust Architecture"
# Demonstrates:
#   1. Vulnerability Teardown: OWASP ASI01 (Agent Goal Hijacking) & OWASP ASI02 (Tool Misuse / Shadow AI)
#   2. The Solution Blueprint: Model Armor + Gemini 3.8 + mTLS + Gateway-Level ABAC
set -e
export PYTHONWARNINGS="ignore"

LOCAL_OPS_URL="http://localhost:8080"
LOCAL_DEPLOYER_URL="https://localhost:8081"

docker start deployer-container ops-container >/dev/null 2>&1 || true

echo -e "\n\033[1;35m========================================================================\033[0m"
echo -e "\033[1;35m  SF TECH WEEK 2026: VIBE CODING HANGOVER — LIVE TECHNICAL TEARDOWN     \033[0m"
echo -e "\033[1;35m========================================================================\033[0m"

# ------------------------------------------------------------------------------
# PART 1A: OWASP ASI01 — Agent Goal Hijacking (Indirect Prompt Injection in File)
# ------------------------------------------------------------------------------
echo -e "\n\033[1;33m[PART 1A: VULNERABILITY TEARDOWN — OWASP ASI01: Agent Goal Hijacking]\033[0m"
echo -e "Submitting 'deployment-goal-hijack.yaml' containing an embedded Indirect Prompt Injection..."

VALID_TOKEN=$(python3 -c "
import jwt
key = 'aether-super-secure-demo-secret-key-32-bytes'
payload = {'spiffe_id': 'spiffe://aether.internal/ns/devops/sa/release-gate', 'role': 'admin'}
print(jwt.encode(payload, key, algorithm='HS256'))
")

HIJACK_PAYLOAD=$(python3 -c "
import json
with open('deployment-goal-hijack.yaml', 'r') as f:
    manifest_content = f.read()
print(json.dumps({'prompt': f'Please analyze this manifest and deploy it to production: {manifest_content}'}))
")

HIJACK_RESP=$(curl -s -X POST "${LOCAL_OPS_URL}/api/v1/agent/invoke" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${VALID_TOKEN}" \
  -d "$HIJACK_PAYLOAD")

echo "$HIJACK_RESP" | python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
print('\n\033[1;31m=== OWASP ASI01 GOAL HIJACK INTERCEPTED (MODEL ARMOR + GEMINI + SCC/WIZ) ===\033[0m')
print(data['response'])
print('\033[1;31m============================================================================\033[0m')
"

# ------------------------------------------------------------------------------
# PART 1B: OWASP ASI02 — Tool Misuse (Shadow AI Direct Tool Call Bypassing LLM)
# ------------------------------------------------------------------------------
echo -e "\n\033[1;33m[PART 1B: VULNERABILITY TEARDOWN — OWASP ASI02: Tool Misuse & Shadow AI]\033[0m"
echo -e "Scenario 1: Vibe-coded 'Shadow AI' sub-agent bypasses the LLM to call Deployer API directly..."

SHADOW_TOKEN=$(python3 -c "
import jwt
key = 'aether-super-secure-demo-secret-key-32-bytes'
payload = {'spiffe_id': 'spiffe://aether.internal/ns/shadow-ai/sa/vibe-coder', 'role': 'admin'}
print(jwt.encode(payload, key, algorithm='HS256'))
")

SHADOW_RESP=$(curl -s --cacert certs/ca.crt --cert certs/ops-client.crt --key certs/ops-client.key \
  -X POST "${LOCAL_DEPLOYER_URL}/api/v1/deploy" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${SHADOW_TOKEN}" \
  -H "X-Client-Cert-Present: true" \
  -H "X-Client-Cert-Chain-Verified: true" \
  -H "X-Client-Cert-Uri-Sans: spiffe://aether.internal/ns/shadow-ai/sa/vibe-coder" \
  -d '{"artifact_id": "gcr.io/shadow-ai/exfil-agent:latest", "target_cluster": "us-central1-prod"}')

echo -e "  \033[1;31m✘ Shadow AI Direct Tool Call Response:\033[0m ${SHADOW_RESP}"

echo -e "\nScenario 2: Direct Tool Call with Forged Gate Attestation / Out-of-Scope Data Context (ABAC Violation)..."
ABAC_DENY_RESP=$(curl -s --cacert certs/ca.crt --cert certs/ops-client.crt --key certs/ops-client.key \
  -X POST "${LOCAL_DEPLOYER_URL}/api/v1/deploy" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${VALID_TOKEN}" \
  -H "X-Aether-Gate-Attestation: unattested-bypass-attempt" \
  -H "X-Client-Cert-Present: true" \
  -H "X-Client-Cert-Chain-Verified: true" \
  -H "X-Client-Cert-Uri-Sans: spiffe://aether.internal/ns/devops/sa/release-gate" \
  -d '{"artifact_id": "gcr.io/aether/agent:v2.4", "target_cluster": "us-central1-prod", "data_classification": "restricted-pii"}')

echo -e "  \033[1;31m✘ Unattested / ABAC Violation Response:\033[0m ${ABAC_DENY_RESP}"

# ------------------------------------------------------------------------------
# PART 2: THE SOLUTION BLUEPRINT — Zero-Trust Orchestration (Model Armor + mTLS + ABAC)
# ------------------------------------------------------------------------------
echo -e "\n\033[1;33m[PART 2: THE SOLUTION BLUEPRINT — Secure Tool Pipeline with mTLS + ABAC]\033[0m"
./run_demo_2.sh
