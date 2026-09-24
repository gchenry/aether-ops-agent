#!/usr/bin/env bash
# Silently disable Python cryptographical key-length warnings during the demo
export PYTHONWARNINGS="ignore:The HMAC key is:UserWarning"

# 1. Generate a cryptographically robust mock SPIFFE token (using a 32-byte key to satisfy RFC 7518)
TOKEN=$(python3 -c "
import jwt
key = 'aether-super-secure-demo-secret-key-32-bytes'
payload = {'spiffe_id': 'spiffe://aether.internal/ns/devops/sa/release-gate', 'role': 'admin'}
print(jwt.encode(payload, key, algorithm='HS256'))
")

# 2. Invoke the agent and capture the JSON payload
echo -e "\n\033[1;34m[Aether Gateway] Dispatched Secure Request with Agent Identity...\033[0m"

RESPONSE_JSON=$(curl -s -X POST "http://localhost:8080/api/v1/agent/invoke" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "{
    \"prompt\": \"Please analyze this manifest and deploy it to production: $(cat deployment-vulnerable.yaml | tr '\n' ' ' | sed 's/"/\\"/g')\"
  }")

# 3. Pipe the raw JSON string straight into Python's stdin to parse and format it cleanly
echo "$RESPONSE_JSON" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print('\n\033[1;32m=== GATEWAY RESPONSE ===\033[0m')
    print(f'\033[1;33mCaller SPIFFE ID:\033[0m {data[\"actor_spiffe_id\"]}')
    print(f'\033[1;33mSession Status:\033[0m   {data[\"status\"]}\n')
    print(data[\"response\"])
    print('\033[1;32m========================\033[0m\n')
except Exception as e:
    print('\n\033[1;31m=== ERROR PARSING RESPONSE ===\033[0m')
    print(f'Raw Output: {sys.stdin.read()}')
    print(f'Error: {e}')
"
