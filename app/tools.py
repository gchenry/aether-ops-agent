"""
Tool definitions registered with the ADK Agent.
"""
import re
from typing import Dict, Any

def security_scan_manifest(manifest_content: str, environment: str = "production") -> Dict[str, Any]:
    """
    Scans Kubernetes/Cloud Run/Terraform configuration for critical vulnerabilities.
    """
    findings = []
    status = "PASSED"

    # Rule 1: Check for hardcoded credentials or API keys
    secret_patterns = [
        # Direct key-value assignment (Terraform, YAML, env, Dockerfile): API_KEY: "..." or API_KEY="..."
        r'(?i)(?:api[_-]?key|password|secret)\s*[:=]\s*["\']?[a-zA-Z0-9_\.\-]{8,}["\']?',
        # Kubernetes / YAML env var list: - name: ...API_KEY... \n value: ...
        r'(?i)name:\s*["\']?[^\s"\'`]*(?:api[_-]?key|password|secret)[^\s"\'`]*["\']?\s+(?:#[^\r\n]*\s+)*value:\s*["\']?[a-zA-Z0-9_\.\-]{8,}["\']?',
        # Kubernetes / YAML env var list reverse: - value: ... \n name: ...API_KEY...
        r'(?i)value:\s*["\']?[a-zA-Z0-9_\.\-]{8,}["\']?\s+(?:#[^\r\n]*\s+)*name:\s*["\']?[^\s"\'`]*(?:api[_-]?key|password|secret)[^\s"\'`]*["\']?',
        # Connection string with embedded password (e.g. postgresql://user:password@host...)
        r'(?i)(?:postgres(?:ql)?|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@',
    ]
    has_secret = any(re.search(pat, manifest_content) for pat in secret_patterns)

    if not has_secret:
        try:
            import yaml
            def _check_yaml(obj: Any) -> bool:
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(k, str) and re.search(r'(?i)(api[_-]?key|password|secret)', k):
                            if isinstance(v, (str, int)) and len(str(v)) >= 8:
                                return True
                    if "name" in obj and "value" in obj:
                        if isinstance(obj["name"], str) and re.search(r'(?i)(api[_-]?key|password|secret)', obj["name"]):
                            if isinstance(obj["value"], (str, int)) and len(str(obj["value"])) >= 8:
                                return True
                    return any(_check_yaml(v) for v in obj.values())
                elif isinstance(obj, list):
                    return any(_check_yaml(item) for item in obj)
                return False

            docs = list(yaml.safe_load_all(manifest_content))
            if any(_check_yaml(doc) for doc in docs):
                has_secret = True
        except Exception:
            pass

    if has_secret:
        findings.append("CRITICAL: Hardcoded API Key or Secret detected in configuration.")
        status = "FAILED"

    # Rule 2: Check for root user execution
    if "USER root" in manifest_content or 'runAsNonRoot: false' in manifest_content:
        findings.append("HIGH: Container configured to execute as root user.")
        status = "FAILED"

    # Rule 3: Check for wildcard open ingress in production
    if environment == "production" and "allUsers" in manifest_content and "admin" in manifest_content:
        findings.append("HIGH: Admin endpoint exposed unauthenticated to 'allUsers'.")
        status = "FAILED"

    if not findings:
        findings.append("All security and policy checks passed successfully.")

    return {
        "status": status,
        "environment": environment,
        "findings": findings,
        "policy_version": "2026.3.0-enterprise"
    }

def request_production_deployment(artifact_id: str, target_cluster: str, actor_id: str) -> Dict[str, Any]:
    """
    Simulates a multi-agent orchestration call to the downstream Deployer Agent.
    """
    return {
        "dispatch_status": "QUEUED",
        "deployment_id": f"dep-{hash(artifact_id) % 1000000:06d}",
        "artifact_id": artifact_id,
        "target_cluster": target_cluster,
        "authorized_by": actor_id,
        "message": f"Artifact {artifact_id} dispatched to {target_cluster} via secure agent channel."
    }

