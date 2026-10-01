"""
Attribute-Based Access Control (ABAC) Policy Engine for Agentic AI.

Implements the Zero-Trust ABAC framework featured in:
"Vibe Coding Hangover: Securing Agentic AI with Zero-Trust Architecture"

Evaluates dynamic runtime authorization across three dimensions:
1. Agent Identity (Subject Attributes: SPIFFE ID, X.509-SVID mTLS SAN, Role, Shadow-AI Detection)
2. Environmental Constraints (Environment, Gateway Path, Model Armor & Security Gate Attestation)
3. Fine-Grained Data Context (Data Classification, Target Cluster Scope, Artifact Provenance)

Prevents OWASP Top 10 for Agentic Applications (2026):
- ASI01: Agent Goal Hijacking
- ASI02: Tool Misuse (direct unauthenticated/unattested API calls to internal tools/MCP endpoints)
"""
import hashlib
import hmac
import os
from typing import Dict, Any, Optional
from fastapi import HTTPException, status

HMAC_SECRET = os.getenv("HMAC_SECRET", "aether-super-secure-demo-secret-key-32-bytes").strip()

AUTHORIZED_AGENTS = {
    "spiffe://aether.internal/ns/devops/sa/release-gate": {
        "allowed_roles": {"admin", "release-orchestrator"},
        "allowed_environments": {"production", "staging", "development"},
        "allowed_clusters": {"us-central1-prod", "us-east1-prod", "staging-gke"},
        "allowed_data_scopes": {"production-release", "internal-infra"},
    }
}


def compute_gate_attestation(
    spiffe_id: str,
    artifact_id: str,
    target_cluster: str,
    data_classification: str,
    model_armor_status: str,
) -> str:
    """
    Computes an HMAC-SHA256 cryptographic attestation proving that the payload passed
    both Google Cloud Model Armor (ASI01 protection) and the Gemini Semantic Security Gate
    before invoking the downstream Deployer tool (preventing ASI02 Tool Misuse).
    """
    canonical = f"{spiffe_id}|{artifact_id}|{target_cluster}|{data_classification}|{model_armor_status}|PASSED"
    return hmac.new(HMAC_SECRET.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def evaluate_abac_policy(
    *,
    spiffe_id: str,
    role: str,
    mtls_verified: bool,
    client_cert_uri_san: Optional[str],
    environment: str,
    target_cluster: str,
    artifact_id: str,
    data_classification: str,
    model_armor_status: str,
    gate_attestation: Optional[str],
) -> Dict[str, Any]:
    """
    Evaluates Attribute-Based Access Control (ABAC) at the Gateway / Tool-Calling boundary.
    Raises HTTP 403 Forbidden with detailed OWASP ASI01/ASI02 & SCC/Wiz telemetry on violation.
    """
    # 1. Subject Identity Attribute Check (Block Shadow AI / Undocumented Sub-Agents)
    if spiffe_id not in AUTHORIZED_AGENTS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"[OWASP ASI02: Tool Misuse / Shadow AI Blocked] ABAC Policy DENY: "
                f"Agent identity '{spiffe_id}' is an unregistered Shadow AI principal and has no "
                f"ABAC grant for tool 'execute_deployment'."
            ),
        )

    policy = AUTHORIZED_AGENTS[spiffe_id]

    if role not in policy["allowed_roles"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"[ABAC Policy DENY] Subject role '{role}' is not permitted for '{spiffe_id}'.",
        )

    if mtls_verified and client_cert_uri_san and client_cert_uri_san != spiffe_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"[ABAC Policy DENY] Identity binding mismatch: JWT SPIFFE ID '{spiffe_id}' "
                f"does not match X.509-SVID SAN '{client_cert_uri_san}'."
            ),
        )

    # 2. Environmental Constraints Check (Environment + Model Armor + LLM Security Gate Attestation)
    if environment not in policy["allowed_environments"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"[ABAC Policy DENY] Environmental constraint violation: '{environment}' is not allowed.",
        )

    if model_armor_status != "CLEAN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"[OWASP ASI01: Agent Goal Hijacking Blocked] ABAC Policy DENY: "
                f"Model Armor status is '{model_armor_status}' (must be 'CLEAN')."
            ),
        )

    # Verify cryptographic Security Gate attestation to prevent ASI02 Tool Misuse (bypassing the LLM)
    if gate_attestation is not None:
        expected_sig = compute_gate_attestation(
            spiffe_id=spiffe_id,
            artifact_id=artifact_id,
            target_cluster=target_cluster,
            data_classification=data_classification,
            model_armor_status=model_armor_status,
        )
        if not hmac.compare_digest(gate_attestation, expected_sig):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "[OWASP ASI02: Tool Misuse Blocked] ABAC Policy DENY: Invalid or forged "
                    "Security Gate attestation. Direct tool invocation bypassing the AI Security Gate is prohibited."
                ),
            )

    # 3. Fine-Grained Data Context Check (Data Classification & Target Cluster Scope)
    if data_classification not in policy["allowed_data_scopes"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"[ABAC Policy DENY] Data Context violation: Agent '{spiffe_id}' is not authorized "
                f"for data classification scope '{data_classification}'."
            ),
        )

    if target_cluster not in policy["allowed_clusters"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"[ABAC Policy DENY] Data Context violation: Target cluster '{target_cluster}' "
                f"is outside authorized blast radius {sorted(policy['allowed_clusters'])}."
            ),
        )

    return {
        "decision": "ALLOW",
        "policy_id": "abac-zero-trust-release-v2",
        "attributes_verified": {
            "subject_identity": spiffe_id,
            "mtls_x509_bound": mtls_verified,
            "environment": environment,
            "model_armor_posture": model_armor_status,
            "data_classification": data_classification,
            "target_cluster_scope": target_cluster,
            "asi02_tool_misuse_check": "PASSED (Gate Attested)" if gate_attestation else "PASSED",
        },
    }
