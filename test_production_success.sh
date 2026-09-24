#!/usr/bin/env bash
# Silence cryptography warnings
export PYTHONWARNINGS="ignore"

PROJECT_ID="your-gcp-project-id"
REGION="us-central1"

# 1. Generate an authenticated SPIFFE token
TOKEN=$(python3 -c "
import jwt
key = 'aether-super-secure-demo-secret-key-32-bytes'
payload = {'spiffe_id': 'spiffe://aether.internal/ns/devops/sa/release-gate', 'role': 'admin'}
print(jwt.encode(payload, key, algorithm='HS256'))
")

# 2. Resolve production Cloud Run endpoint and IAM Identity Token
ID_TOKEN=$(gcloud auth print-identity-token)
OPS_URL=$(gcloud run services describe aether-ops-agent --project="${PROJECT_ID}" --region="${REGION}" --format='value(status.url)')

# 3. Read and serialize the clean manifest safely using Python
PAYLOAD=$(python3 -c "
import json
with open('deployment-compliant.yaml', 'r') as f:
    manifest_content = f.read()
print(json.dumps({'prompt': f'Please analyze this manifest and deploy it to production: {manifest_content}'}))
")

echo -e "\033[1;34m[Aether Ops] Sending Compliant Manifest to Production Gate...\033[0m"
echo -e "Route: \033[1;36m${OPS_URL}/api/v1/agent/invoke\033[0m\n"

# 4. Invoke the live agent
RESPONSE_JSON=$(curl -s -X POST "${OPS_URL}/api/v1/agent/invoke" \
  -H "Content-Type: application/json" \
  -H "X-Serverless-Authorization: Bearer ${ID_TOKEN}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "$PAYLOAD")

# 5. Print the beautifully rendered success response
echo "$RESPONSE_JSON" | python3 -c "
import json, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
    print('\n\033[1;32m=== LIVE PRODUCTION DEPLOY SUCCESS ===\033[0m')
    print(f'\033[1;33mCaller Identity:\033[0m {data[\"actor_spiffe_id\"]}')
    print(f'\033[1;33mGate Status:\033[0m     {data[\"status\"]}\n')
    print(data[\"response\"])
    print('\033[1;32m======================================\033[0m\n')
except Exception as e:
    print('\n\033[1;31m=== ERROR PARSING PRODUCTION RESPONSE ===\033[0m')
    print(f'Raw Output: {raw}')
"
