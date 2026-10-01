#!/usr/bin/env bash
# Verify Mutual TLS (mTLS) SPIFFE X.509-SVID Handshake, Certificate Chain & LB Policy Headers
set -e
export PYTHONWARNINGS="ignore"

echo -e "\n\033[1;34m================================================================\033[0m"
echo -e "\033[1;34m  AETHER OPS: MUTUAL TLS (mTLS) X.509-SVID VERIFICATION SUITE   \033[0m"
echo -e "\033[1;34m================================================================\033[0m\n"

# 1. Generate / Verify SPIFFE X.509-SVID PKI and GCP TrustConfig/ServerTlsPolicy artifacts
echo -e "\033[1;33m[1/4] Verifying SPIFFE X.509-SVID Certificates & GCP TrustConfig...\033[0m"
./generate_mtls_certs.py

# 2. Run Python mTLS & SPIFFE Security Unit Tests
echo -e "\033[1;33m[2/4] Running mTLS & Cloud Load Balancer Policy Unit Tests...\033[0m"
./tests/test_security.py

# 3. Verify Socket-Level TLS 1.3 mTLS Handshake on deployer-container
echo -e "\n\033[1;33m[3/4] Testing Socket-Level TLS 1.3 mTLS Handshake (ssl.CERT_REQUIRED)...\033[0m"
docker start deployer-container ops-container >/dev/null 2>&1 || true

echo -n "  - Unauthenticated TLS connection (no client cert): "
if curl -s --max-time 5 --cacert certs/ca.crt https://localhost:8081/health >/dev/null 2>&1; then
    echo -e "\033[1;31mFAILED (Connection should have been rejected by TLS handshake)\033[0m"
    exit 1
else
    echo -e "\033[1;32mREJECTED AT TLS HANDSHAKE (Expected)\033[0m"
fi

echo -n "  - Mutual TLS connection (with ops-client.crt):     "
MTLS_HEALTH=$(curl -s --max-time 5 \
  --cacert certs/ca.crt \
  --cert certs/ops-client.crt \
  --key certs/ops-client.key \
  https://localhost:8081/health)
if [[ "$MTLS_HEALTH" == *"healthy"* ]]; then
    echo -e "\033[1;32mACCEPTED (${MTLS_HEALTH})\033[0m"
else
    echo -e "\033[1;31mFAILED (${MTLS_HEALTH})\033[0m"
    exit 1
fi

# 4. Execute End-to-End Agent-to-Agent Deployment over mTLS
echo -e "\n\033[1;33m[4/4] Verifying End-to-End Ops -> Deployer Agent Handoff over mTLS...\033[0m"
./run_demo_2.sh
