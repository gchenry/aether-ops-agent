#!/usr/bin/env python3
"""
Generates SPIFFE X.509-SVID Certificates and Google Cloud Certificate Manager /
ServerTlsPolicy configurations for Mutual TLS (mTLS).
"""
import os
import sys

_ROOT = os.path.abspath(os.path.dirname(__file__))
_VENV_DIR = os.path.join(_ROOT, ".venv")
_VENV_PY = os.path.join(_VENV_DIR, "bin", "python")
if os.path.exists(_VENV_PY) and os.path.abspath(sys.prefix) != os.path.abspath(_VENV_DIR):
    os.execv(_VENV_PY, [_VENV_PY, *sys.argv])
sys.path.insert(0, _ROOT)

from app.mtls import ensure_mtls_certificates, get_client_cert_metadata

if __name__ == "__main__":
    force = "--force" in sys.argv
    paths = ensure_mtls_certificates(force=force)
    meta = get_client_cert_metadata()

    print("\n================================================================")
    print("  AETHER OPS: SPIFFE X.509-SVID & GCP mTLS ARTIFACTS GENERATED  ")
    print("================================================================")
    print(f"  ✔ Root CA Bundle:         {paths['ca_cert']}")
    print(f"  ✔ Ops Client X.509-SVID:  {paths['client_cert']}")
    print(f"  ✔ Ops Client Private Key: {paths['client_key']}")
    print(f"  ✔ Deployer Server SVID:   {paths['server_cert']}")
    print(f"  ✔ Deployer Server Key:    {paths['server_key']}")
    print(f"  ✔ GCP TrustConfig YAML:   {paths['trust_config_yaml']}")
    print(f"  ✔ GCP ServerTlsPolicy:    {paths['server_tls_policy_yaml']}")
    print("----------------------------------------------------------------")
    print(f"  Client X.509 SAN URI:     {meta['uri_san']}")
    print(f"  Client Cert SHA-256 FP:   {meta['sha256_fingerprint']}")
    print(f"  Client Cert Serial:       {meta['serial']}")
    print("================================================================\n")
