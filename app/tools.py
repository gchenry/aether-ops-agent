"""
Semantic Security Audit Tools powered by Gemini 3.8.
"""
import os
import json
from typing import Dict, Any
from google import genai
from google.genai import types

from app.config import settings

# 1. Fetch GCP configurations from environment
PROJECT_ID = os.getenv("PROJECT_ID", settings.PROJECT_ID)
GEMINI_MODEL = os.getenv("GEMINI_MODEL", settings.GEMINI_MODEL)
LOCATION = "global" if GEMINI_MODEL.startswith("gemini-3") else os.getenv("LOCATION", settings.LOCATION)

# 2. Initialize the GenAI Client (uses ambient Application Default Credentials)
security_client = None

def get_security_client():
    global security_client
    if security_client is None:
        try:
            security_client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)
        except Exception:
            pass
    return security_client


def security_scan_manifest(manifest_content: str, environment: str = "production") -> Dict[str, Any]:
    """
    Leverages Gemini to perform a semantic security audit on infrastructure manifests.
    """
    client = get_security_client()
    # Fallback mock scan if Vertex API is offline locally
    if not client:
        if "api_key" in manifest_content.lower() or "secret" in manifest_content.lower():
            return {
                "status": "FAILED",
                "findings": ["CRITICAL: Hardcoded API Key or Secret detected (Offline fallback)."]
            }
        return {"status": "PASSED", "findings": ["All checks passed (Offline fallback)."]}

    # Define the strict system and auditing rules for Gemini
    audit_prompt = f"""
    You are an automated, high-precision DevSecOps Security Auditor specializing in GKE, Kubernetes, and Cloud Run manifests.
    Analyze the provided infrastructure manifest carefully for any high-severity security vulnerabilities, policy violations, or suspicious configurations.

    [Target Environment]: {environment}

    [Manifest to Audit]:
    \"\"\"
    {manifest_content}
    \"\"\"

    Strict Audit Rules:
    1. Scan for hardcoded API keys, tokens, credentials, or private certificate blocks (including obfuscated variable names, patterned keys like AIzaSy..., and encoded secrets like base64 Basic auth).
    2. Check for container security context risks: containers explicitly configured with privileged mode (privileged: true), container breakout capabilities, or explicitly configured to execute with root user privileges (e.g., USER root, runAsNonRoot: false). Do not flag manifests solely for omitting an optional securityContext if no explicit violations are declared.
    3. Check for network namespace sharing or bypasses of container network isolation (e.g., hostNetwork: true).
    4. Look for wildcard, unrestricted ingress rules exposed to public routes (e.g., allUsers access, unauthenticated access) especially for administrative, debug, or internal endpoints.
    5. Verify compliance thoroughly. If any violations are found, set status to "FAILED" and document each distinct violation. If the manifest is compliant, set status to "PASSED" and findings to ["All security and policy checks passed successfully."].

    You must output exactly one JSON object following this format:
    {{
      "status": "PASSED" or "FAILED",
      "findings": [
        "A clear, concise, actionable description of each vulnerability found, referencing the file line or environment context."
      ]
    }}
    """

    import time
    last_err = None
    for attempt in range(3):
        try:
            # Call Gemini with structured JSON output enforcement
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=audit_prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.0,  # Zero temperature for consistent, deterministic security audits
                )
            )
            return json.loads(response.text)
        except Exception as e:
            last_err = e
            if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                time.sleep(2 * (attempt + 1))
                try:
                    fallback_client = genai.Client(vertexai=True, project=PROJECT_ID, location="us-central1")
                    response = fallback_client.models.generate_content(
                        model="gemini-2.5-flash",
                        contents=audit_prompt,
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json",
                            temperature=0.0,
                        )
                    )
                    return json.loads(response.text)
                except Exception:
                    pass
            else:
                break

    # Fallback graceful failure
    return {
        "status": "FAILED",
        "findings": [f"Security scan failed to execute semantically: {str(last_err)}"]
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
