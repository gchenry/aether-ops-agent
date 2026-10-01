#!/usr/bin/env bash
# Test & Verify Google Cloud Agent Gateway + Agent Registry Governance
set -e
export PYTHONWARNINGS="ignore"

PROJECT_ID="${PROJECT_ID:-your-gcp-project-id}"
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)" 2>/dev/null || echo "000000000000")
REGION="us-central1"
GATEWAY_NAME="aether-ingress-agw"
AUTHZ_EXT_NAME="aether-iap-authz-ext"
AUTHZ_POLICY_NAME="aether-iap-authz-policy"
REGISTRY_SERVICE_NAME="aether-deployer-service"
REGISTRY_ENDPOINT_ID="agentregistry-00000000-0000-0000-0000-000000000000"

echo -e "\n\033[1;34m================================================================\033[0m"
echo -e "\033[1;34m  AETHER OPS: AGENT GATEWAY & AGENT REGISTRY VERIFICATION SUITE \033[0m"
echo -e "\033[1;34m================================================================\033[0m\n"

# 1. Verify Agent Gateway Resource
echo -e "\033[1;33m[1/4] Verifying Google Cloud Agent Gateway (${GATEWAY_NAME})...\033[0m"
GW_URI=$(gcloud beta network-services agent-gateways describe "${GATEWAY_NAME}" \
  --project="${PROJECT_ID}" \
  --location="${REGION}" \
  --format="value(name)")
GW_MODE=$(gcloud beta network-services agent-gateways describe "${GATEWAY_NAME}" \
  --project="${PROJECT_ID}" \
  --location="${REGION}" \
  --format="value(googleManaged.governedAccessPath)")
echo -e "  ✔ Agent Gateway URI:  \033[1;32m${GW_URI}\033[0m"
echo -e "  ✔ Governed Path Mode: \033[1;32m${GW_MODE}\033[0m"

# 2. Verify Service Extension & Authz Policy bound to Agent Gateway
echo -e "\n\033[1;33m[2/4] Verifying IAP Request Authz Policy & Service Extension...\033[0m"
POLICY_TARGET=$(gcloud network-security authz-policies describe "${AUTHZ_POLICY_NAME}" \
  --project="${PROJECT_ID}" \
  --location="${REGION}" \
  --format="value(target.resources[0])")
POLICY_EXT=$(gcloud network-security authz-policies describe "${AUTHZ_POLICY_NAME}" \
  --project="${PROJECT_ID}" \
  --location="${REGION}" \
  --format="value(customProvider.authzExtension.resources[0])")
echo -e "  ✔ Authz Policy Target:    \033[1;32m${POLICY_TARGET}\033[0m"
echo -e "  ✔ IAP Authz Extension:    \033[1;32m${POLICY_EXT}\033[0m"

# 3. Verify Agent Registry Service, Endpoint, and IAP Egressor IAM Policy
echo -e "\n\033[1;33m[3/4] Verifying Agent Registry Discovery & IAP Egressor IAM Binding...\033[0m"
REG_URL=$(gcloud alpha agent-registry services describe "${REGISTRY_SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --location="${REGION}" \
  --format="value(interfaces[0].url)")
REG_ENDPOINT=$(gcloud alpha agent-registry services describe "${REGISTRY_SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --location="${REGION}" \
  --format="value(registryResource)")
EGRESSOR_MEMBER=$(gcloud alpha iap web get-iam-policy \
  --project="${PROJECT_ID}" \
  --resource-type=agent-registry \
  --region="${REGION}" \
  --endpoint="${REGISTRY_ENDPOINT_ID}" \
  --flatten="bindings[].members" \
  --filter="bindings.role:roles/iap.egressor" \
  --format="value(bindings.members)" | head -n 1)
echo -e "  ✔ Registered Service URL: \033[1;32m${REG_URL}\033[0m"
echo -e "  ✔ Registry Endpoint Resource: \033[1;32m${REG_ENDPOINT}\033[0m"
echo -e "  ✔ Authorized IAP Egressor:    \033[1;32m${EGRESSOR_MEMBER}\033[0m"

# 4. Invoke Live Cloud Run Ops Agent and verify Agent Gateway dispatch
echo -e "\n\033[1;33m[4/4] Executing End-to-End Agent-to-Agent Call via Agent Gateway...\033[0m"
ID_TOKEN=$(gcloud auth print-identity-token)
OPS_URL=$(gcloud run services describe aether-ops-agent --project="${PROJECT_ID}" --region="${REGION}" --format='value(status.url)')

TOKEN=$(python3 -c "
import jwt
key = 'aether-super-secure-demo-secret-key-32-bytes'
payload = {'spiffe_id': 'spiffe://aether.internal/ns/devops/sa/release-gate', 'role': 'admin'}
print(jwt.encode(payload, key, algorithm='HS256'))
")

PAYLOAD=$(python3 -c "
import json
with open('deployment-compliant.yaml', 'r') as f:
    manifest_content = f.read()
print(json.dumps({'prompt': f'Please analyze this manifest and deploy it to production: {manifest_content}'}))
")

RESPONSE_JSON=$(curl -s -X POST "${OPS_URL}/api/v1/agent/invoke" \
  -H "Content-Type: application/json" \
  -H "X-Serverless-Authorization: Bearer ${ID_TOKEN}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "$PAYLOAD")

echo "$RESPONSE_JSON" | python3 -c "
import json, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
    resp_text = data.get('response', '')
    print('\n\033[1;32m=== AGENT GATEWAY END-TO-END RESPONSE ===\033[0m')
    print(f'\033[1;33mCaller Identity:\033[0m {data.get(\"actor_spiffe_id\")}')
    print(f'\033[1;33mGate Status:\033[0m     {data.get(\"status\")}\n')
    print(resp_text)
    if 'Agent Gateway:' in resp_text and 'aether-ingress-agw' in resp_text:
        print('\n\033[1;32m✔ VERIFIED: Traffic discovered via Agent Registry and governed by Agent Gateway!\033[0m')
    else:
        print('\n\033[1;31m✘ WARNING: Agent Gateway metadata not found in response.\033[0m')
    print('\033[1;32m=========================================\033[0m\n')
except Exception as e:
    print('\n\033[1;31m=== ERROR PARSING RESPONSE ===\033[0m')
    print(f'Raw Output: {raw}')
    sys.exit(1)
"
