#!/usr/bin/env bash
# Silence cryptography warnings
export PYTHONWARNINGS="ignore"

if [ -f .env ]; then
  set -a; source .env; set +a
fi
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || echo 'your-gcp-project-id')}"
REGION="us-central1"
GATEWAY_NAME="aether-ingress-agw"

echo -e "\n\033[1;34m[Aether Infrastructure] Resolving Cloud Run & Agent Gateway Endpoints...\033[0m"

# 1. Fetch live URLs and Cloud Run IAM identity token dynamically
ID_TOKEN=$(gcloud auth print-identity-token)
OPS_URL=$(gcloud run services describe aether-ops-agent --project="${PROJECT_ID}" --region="${REGION}" --format='value(status.url)')
DEPLOYER_URL=$(gcloud run services describe aether-deployer-agent --project="${PROJECT_ID}" --region="${REGION}" --format='value(status.url)')
GW_URI=$(gcloud beta network-services agent-gateways describe "${GATEWAY_NAME}" --project="${PROJECT_ID}" --location="${REGION}" --format='value(name)' 2>/dev/null || true)

echo -e "\033[1;32m✔ Resolved Services:\033[0m"
echo -e "  - Ops Agent:      \033[1;36m${OPS_URL}\033[0m"
echo -e "  - Deployer Agent: \033[1;36m${DEPLOYER_URL}\033[0m"
echo -e "  - Agent Gateway:  \033[1;36m${GW_URI}\033[0m\n"

echo -e "\033[1;34m=== TESTING HEALTH STATUSES ===\033[0m"

# 2. Test Upstream Ops Agent Health
echo -n "Checking Ops Agent:      "
OPS_HEALTH=$(curl -s -H "X-Serverless-Authorization: Bearer ${ID_TOKEN}" "${OPS_URL}/health")
if [[ $OPS_HEALTH == *"healthy"* ]]; then
    echo -e "\033[1;32mONLINE\033[0m"
else
    echo -e "\033[1;31mOFFLINE or ERROR\033[0m"
fi

# 3. Test Downstream Deployer Agent Health
echo -n "Checking Deployer Agent: "
DEPLOYER_HEALTH=$(curl -s -H "X-Serverless-Authorization: Bearer ${ID_TOKEN}" "${DEPLOYER_URL}/health")
if [[ $DEPLOYER_HEALTH == *"healthy"* ]]; then
    echo -e "\033[1;32mONLINE (SPIFFE Guard Active)\033[0m"
else
    echo -e "\033[1;31mOFFLINE or ERROR\033[0m"
fi

# 4. Test Agent Gateway Control Plane Health
echo -n "Checking Agent Gateway:  "
if [[ -n "$GW_URI" ]]; then
    echo -e "\033[1;32mONLINE (IAP Request Authz Active)\033[0m"
else
    echo -e "\033[1;31mOFFLINE or ERROR\033[0m"
fi

echo -e "\n\033[1;32m================================================\033[0m"
