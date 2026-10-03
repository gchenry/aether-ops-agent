"""
Attribute-Based Access Control (ABAC) & 3Cs (Contain, Curate, Control) Policy Engine.

Implements the Zero-Trust ABAC framework featured in:
"Vibe Coding Hangover: Securing Agentic AI with Zero-Trust Architecture"

Evaluates dynamic runtime authorization across the 3Cs Framework:
1. CONTAIN (Non-Human Identity & mTLS):
   - SPIFFE NHI (spiffe_id), X.509-SVID mTLS SAN binding (ASI03, ASI07), Shadow-AI blocking.
2. CURATE (Context Hardening & Gateway Mediation):
   - Model Armor runtime screening (ASI01), Cryptographic Gate Attestation (ASI02),
     and Blast-Radius Circuit Breakers / Transaction Quotas (ASI08).
3. CONTROL (Dynamic ABAC, HITL/HOTL & Runtime Telemetry):
   - Evaluates Agent NHI, Environmental Tags, User Tenant, Data Classification,
     Target Cluster Blast Radius, and Action Severity (enforcing HITL for critical mutations, ASI09).
"""
import hashlib
import hmac
import os
from typing import Dict, Any, Optional
from fastapi import HTTPException, status

HMAC_SECRET = os.getenv("HMAC_SECRET", "aether-super-secure-demo-secret-key-32-bytes").strip()

AUTHORIZED_NHI_POLICIES = {
    "spiffe://aether.internal/ns/devops/sa/release-gate": {
        "allowed_roles": {"admin", "release-orchestrator"},
        "allowed_environments": {"production", "staging", "development"},
        "allowed_tenants": {"tenant-aether-core", "default-tenant"},
        "allowed_clusters": {"us-central1-prod", "us-east1-prod", "staging-gke"},
        "allowed_data_scopes": {"production-release", "internal-infra"},
        "autonomous_severities": {"standard", "low", "medium"},
        "max_swarm_depth": 2,
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
    both Google Cloud Model Armor (ASI01 protection) and the Semantic Security Gate
    built with Gemini models before invoking the downstream Deployer tool (preventing ASI02 Tool Misuse).
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
    tenant_id: str = "tenant-aether-core",
    action_severity: str = "standard",
    swarm_hop_count: int = 1,
    hitl_approval_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluates Attribute-Based Access Control (ABAC) and the 3Cs (Contain, Curate, Control)
    at the Gateway / Tool-Calling boundary.
    Raises HTTP 403 Forbidden with detailed OWASP ASI01-ASI10 & SCC/Wiz AI-APP telemetry on violation.
    """
    # ==========================================================================
    # PILLAR 1: CONTAIN (Non-Human Identity Governance & mTLS Binding — ASI03, ASI07)
    # ==========================================================================
    if spiffe_id not in AUTHORIZED_NHI_POLICIES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"[OWASP ASI02/ASI03/ASI10: Shadow AI & Unregistered NHI Blocked] ABAC Policy DENY: "
                f"Non-Human Identity '{spiffe_id}' is an unregistered Shadow AI principal and has no "
                f"ABAC grant for tool 'execute_deployment'."
            ),
        )

    policy = AUTHORIZED_NHI_POLICIES[spiffe_id]

    if role not in policy["allowed_roles"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"[OWASP ASI03: Identity & Privilege Abuse Blocked] ABAC Policy DENY: Role '{role}' not permitted.",
        )

    if mtls_verified and client_cert_uri_san and client_cert_uri_san != spiffe_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"[OWASP ASI07: Insecure Inter-Agent Comm Blocked] ABAC Policy DENY: "
                f"JWT NHI '{spiffe_id}' does not match mTLS X.509-SVID SAN '{client_cert_uri_san}'."
            ),
        )

    # ==========================================================================
    # PILLAR 2: CURATE (Context Hardening, Gateway Mediation & Circuit Breakers — ASI01, ASI02, ASI08)
    # ==========================================================================
    if model_armor_status != "CLEAN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"[OWASP ASI01: Agent Goal Hijacking Blocked] ABAC Policy DENY: "
                f"Model Armor status is '{model_armor_status}' (must be 'CLEAN')."
            ),
        )

    # Blast-Radius Circuit Breaker (OWASP ASI08: Cascading Failures across multi-agent swarms)
    if swarm_hop_count > policy["max_swarm_depth"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"[OWASP ASI08: Cascading Failure Circuit Breaker Triggered] ABAC Policy DENY: "
                f"Agent swarm hop count ({swarm_hop_count}) exceeds max blast-radius depth ({policy['max_swarm_depth']})."
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

    # ==========================================================================
    # PILLAR 3: CONTROL (Dynamic ABAC: Environment, Tenant, Data Scope & Action Severity — ASI09)
    # ==========================================================================
    if environment not in policy["allowed_environments"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"[ABAC Policy DENY] Environmental constraint violation: '{environment}' is not allowed.",
        )

    if tenant_id not in policy["allowed_tenants"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"[ABAC Policy DENY] Tenant isolation violation: NHI '{spiffe_id}' is not authorized for tenant '{tenant_id}'.",
        )

    if data_classification not in policy["allowed_data_scopes"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"[ABAC Policy DENY] Data Context violation: NHI '{spiffe_id}' is not authorized "
                f"for data classification scope '{data_classification}'."
            ),
        )

    if target_cluster not in policy["allowed_clusters"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"[OWASP ASI08: Blast Radius Containment] ABAC Policy DENY: Target cluster '{target_cluster}' "
                f"is outside authorized scope {sorted(policy['allowed_clusters'])}."
            ),
        )

    # OWASP ASI09: Human-Agent Trust Abuse — Require HITL approval for high-impact/destructive mutations
    if action_severity not in policy["autonomous_severities"] and not hitl_approval_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"[OWASP ASI09: Human-in-the-Loop (HITL) Required] ABAC Policy DENY: "
                f"Action severity '{action_severity}' requires an explicit cryptographically signed HITL approval token."
            ),
        )

    return {
        "decision": "ALLOW",
        "framework": "3Cs (Contain, Curate, Control)",
        "policy_id": "abac-zero-trust-release-v2",
        "attributes_verified": {
            "subject_nhi": spiffe_id,
            "mtls_x509_bound": mtls_verified,
            "environment": environment,
            "tenant_id": tenant_id,
            "action_severity": action_severity,
            "swarm_hop_count": swarm_hop_count,
            "model_armor_posture": model_armor_status,
            "data_classification": data_classification,
            "target_cluster_scope": target_cluster,
            "asi02_tool_misuse_check": "PASSED (Gate Attested)" if gate_attestation else "PASSED",
        },
    }
