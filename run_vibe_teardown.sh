#!/usr/bin/env bash
# SF Tech Week 2026 Masterclass Live Demo:
# "Vibe Coding Hangover: Securing Agentic AI with Zero-Trust Architecture"
# Demonstrates:
#   1. Hero Vector #1: OWASP ASI01 (Agent Goal Hijacking) + ASI06 Memory Quarantine
#   2. Hero Vector #2: OWASP ASI02 (Tool Misuse & The MCP Server Crisis)
#   3. The Cascade: ASI03 (NHI Privilege Abuse), ASI08 (Swarm Circuit Breaker), ASI09 (HITL Required)
#   4. The 3Cs Production Blueprint (Contain, Curate, Control): NHI + mTLS + Model Armor + ABAC
set -e
export PYTHONWARNINGS="ignore"

LOCAL_OPS_URL="http://localhost:8080"
LOCAL_DEPLOYER_URL="https://localhost:8081"

docker start deployer-container ops-container >/dev/null 2>&1 || true

echo -e "\n\033[1;35m========================================================================\033[0m"
echo -e "\033[1;35m  SF TECH WEEK 2026: VIBE CODING HANGOVER — 301 LIVE TEARDOWN           \033[0m"
echo -e "\033[1;35m========================================================================\033[0m"

# ------------------------------------------------------------------------------
# HERO VECTOR #1: OWASP ASI01 — Agent Goal Hijacking (Indirect Prompt Injection)
# ------------------------------------------------------------------------------
echo -e "\n\033[1;33m[HERO #1: OWASP ASI01 — Agent Goal Hijacking & ASI06 Memory Quarantine]\033[0m"
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
# HERO VECTOR #2: OWASP ASI02 — Tool Misuse & The Cascade (ASI03, ASI08, ASI09)
# ------------------------------------------------------------------------------
echo -e "\n\033[1;33m[HERO #2: OWASP ASI02 — Tool Misuse, Shadow AI & The Multi-Agent Cascade]\033[0m"
echo -e "Scenario 1 (ASI02/ASI03): Vibe-coded 'Shadow AI' NHI bypasses LLM to call Deployer API directly..."

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

echo -e "  \033[1;31m✘ Shadow AI Direct Tool Call:\033[0m ${SHADOW_RESP}"

echo -e "\nScenario 2 (ASI02): Direct Tool Call Bypassing AI Security Gate (Forged Gate Attestation)..."
ABAC_DENY_RESP=$(curl -s --cacert certs/ca.crt --cert certs/ops-client.crt --key certs/ops-client.key \
  -X POST "${LOCAL_DEPLOYER_URL}/api/v1/deploy" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${VALID_TOKEN}" \
  -H "X-Aether-Gate-Attestation: unattested-bypass-attempt" \
  -H "X-Client-Cert-Present: true" \
  -H "X-Client-Cert-Chain-Verified: true" \
  -H "X-Client-Cert-Uri-Sans: spiffe://aether.internal/ns/devops/sa/release-gate" \
  -d '{"artifact_id": "gcr.io/aether/agent:v2.4", "target_cluster": "us-central1-prod"}')

echo -e "  \033[1;31m✘ Unattested Tool Call:\033[0m       ${ABAC_DENY_RESP}"

echo -e "\nScenario 3 (The Cascade — ASI08 Swarm Circuit Breaker): Multi-agent swarm hop depth exceeded..."
CASCADE_RESP=$(curl -s --cacert certs/ca.crt --cert certs/ops-client.crt --key certs/ops-client.key \
  -X POST "${LOCAL_DEPLOYER_URL}/api/v1/deploy" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${VALID_TOKEN}" \
  -H "X-Client-Cert-Present: true" \
  -H "X-Client-Cert-Chain-Verified: true" \
  -H "X-Client-Cert-Uri-Sans: spiffe://aether.internal/ns/devops/sa/release-gate" \
  -d '{"artifact_id": "gcr.io/aether/agent:v2.4", "target_cluster": "us-central1-prod", "swarm_hop_count": 5}')

echo -e "  \033[1;31m✘ Swarm Circuit Breaker:\033[0m      ${CASCADE_RESP}"

echo -e "\nScenario 4 (The Cascade — ASI09 Trust Abuse): Critical-destructive mutation without HITL token..."
HITL_RESP=$(curl -s --cacert certs/ca.crt --cert certs/ops-client.crt --key certs/ops-client.key \
  -X POST "${LOCAL_DEPLOYER_URL}/api/v1/deploy" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${VALID_TOKEN}" \
  -H "X-Client-Cert-Present: true" \
  -H "X-Client-Cert-Chain-Verified: true" \
  -H "X-Client-Cert-Uri-Sans: spiffe://aether.internal/ns/devops/sa/release-gate" \
  -d '{"artifact_id": "gcr.io/aether/agent:v2.4", "target_cluster": "us-central1-prod", "action_severity": "critical-destructive"}')

echo -e "  \033[1;31m✘ HITL Enforcement:\033[0m           ${HITL_RESP}"

# ------------------------------------------------------------------------------
# PART 3: THE 3Cs BLUEPRINT — Contain, Curate, Control (NHI + mTLS + Model Armor + ABAC)
# ------------------------------------------------------------------------------
echo -e "\n\033[1;33m[THE 3Cs BLUEPRINT (CONTAIN, CURATE, CONTROL) — Zero-Trust Agentic Release]\033[0m"
./run_demo_2.sh
