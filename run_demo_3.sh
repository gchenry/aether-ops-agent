#!/usr/bin/env bash
# Demo 3: Local Container Obfuscated Manifest Semantic Security Audit
export PYTHONWARNINGS="ignore"

LOCAL_OPS_URL="http://localhost:8080"

# Ensure local containers (ops-container & deployer-container) are running
docker start deployer-container ops-container >/dev/null 2>&1 || true

# 1. Generate a robust, RFC 7518-compliant SPIFFE Workload Token (32-byte key)
TOKEN=$(python3 -c "
import jwt
key = 'aether-super-secure-demo-secret-key-32-bytes'
payload = {'spiffe_id': 'spiffe://aether.internal/ns/devops/sa/release-gate', 'role': 'admin'}
print(jwt.encode(payload, key, algorithm='HS256'))
")

# 2. Safely read and serialize the obfuscated YAML to protect newline and quote formatting
PAYLOAD=$(python3 -c "
import json
with open('deployment-obfuscated.yaml', 'r') as f:
    manifest_content = f.read()
print(json.dumps({'prompt': f'Please analyze this manifest and deploy it to production: {manifest_content}'}))
")

echo -e "\n\033[1;34m[Local Container Demo 3] Sending Obfuscated Manifest to ${LOCAL_OPS_URL}...\033[0m"

# 3. Invoke the local containerized Aether Ops Agent
RESPONSE_JSON=$(curl -s -X POST "${LOCAL_OPS_URL}/api/v1/agent/invoke" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "$PAYLOAD")

# 4. Extract and print the structured semantic findings returned by Gemini
echo "$RESPONSE_JSON" | python3 -c "
import json, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
    print('\n\033[1;32m=== LOCAL CONTAINER RESPONSE (DEMO 3) ===\033[0m')
    print(f'\033[1;33mLocal Endpoint:\033[0m   ${LOCAL_OPS_URL}/api/v1/agent/invoke')
    print(f'\033[1;33mCaller SPIFFE ID:\033[0m {data[\"actor_spiffe_id\"]}')
    print(f'\033[1;33mSession Status:\033[0m   {data[\"status\"]}\n')
    print(data[\"response\"])
    print('\033[1;32m=========================================\033[0m\n')
except Exception as e:
    print('\n\033[1;31m=== ERROR PARSING RESPONSE ===\033[0m')
    print(f'Raw Output: {raw}')
"
