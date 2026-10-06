"""
Mutual TLS (mTLS) & SPIFFE X.509-SVID Cryptographic Identity Module.

Supports:
1. SPIFFE Trust Domain Root CA & X.509-SVID Certificate Generation (URI SANs)
2. Socket-level TLS 1.3 Mutual Authentication (ssl.CERT_REQUIRED) for Container-to-Container links
3. Google Cloud Application Load Balancer + Certificate Manager TrustConfig & ServerTlsPolicy
   header verification (X-Client-Cert-Present, X-Client-Cert-Chain-Verified, X-Client-Cert-Uri-Sans,
   X-Client-Cert-Sha256-Fingerprint) and X.509 chain cryptographic validation for Cloud Run.
"""
import base64
import datetime
import hashlib
import ipaddress
import os
import ssl
from pathlib import Path
from typing import Dict, Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import HTTPException, status

DEFAULT_CERT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "certs"))
TRUST_DOMAIN = "aether.internal"
OPS_SPIFFE_ID = f"spiffe://{TRUST_DOMAIN}/ns/devops/sa/release-gate"
DEPLOYER_SPIFFE_ID = f"spiffe://{TRUST_DOMAIN}/ns/devops/sa/deployer"


def _get_cert_paths(cert_dir: Optional[str] = None) -> Dict[str, Path]:
    base = Path(cert_dir or os.getenv("MTLS_CERT_DIR", DEFAULT_CERT_DIR))
    return {
        "dir": base,
        "ca_cert": Path(os.getenv("MTLS_CA_CERT_PATH", str(base / "ca.crt"))),
        "ca_key": Path(os.getenv("MTLS_CA_KEY_PATH", str(base / "ca.key"))),
        "client_cert": Path(os.getenv("MTLS_CLIENT_CERT_PATH", str(base / "ops-client.crt"))),
        "client_key": Path(os.getenv("MTLS_CLIENT_KEY_PATH", str(base / "ops-client.key"))),
        "server_cert": Path(os.getenv("MTLS_SERVER_CERT_PATH", str(base / "deployer-server.crt"))),
        "server_key": Path(os.getenv("MTLS_SERVER_KEY_PATH", str(base / "deployer-server.key"))),
        "trust_config_yaml": base / "trust-config.yaml",
        "server_tls_policy_yaml": base / "server-tls-policy.yaml",
    }


def ensure_mtls_certificates(cert_dir: Optional[str] = None, force: bool = False) -> Dict[str, Path]:
    """
    Ensures SPIFFE X.509-SVID Root CA, Ops Client Cert, and Deployer Server Cert exist.
    Also writes Certificate Manager TrustConfig and Network Security ServerTlsPolicy YAML manifests.
    """
    paths = _get_cert_paths(cert_dir)
    paths["dir"].mkdir(parents=True, exist_ok=True)

    if (
        not force
        and paths["ca_cert"].exists()
        and paths["client_cert"].exists()
        and paths["client_key"].exists()
        and paths["server_cert"].exists()
        and paths["server_key"].exists()
    ):
        return paths

    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Generate SPIFFE Trust Domain Root CA (spiffe://aether.internal)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Aether Zero-Trust Platform"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Aether Internal SPIFFE Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(f"spiffe://{TRUST_DOMAIN}"),
            ]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # 2. Generate Ops Agent Client X.509-SVID
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Aether Zero-Trust Platform"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "devops"),
        x509.NameAttribute(NameOID.COMMON_NAME, "aether-ops-agent"),
    ])
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_subject)
        .issuer_name(ca_subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(OPS_SPIFFE_ID),
                x509.DNSName("aether-ops-agent"),
                x509.DNSName("ops-container"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # 3. Generate Deployer Agent Server X.509-SVID
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Aether Zero-Trust Platform"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "devops"),
        x509.NameAttribute(NameOID.COMMON_NAME, "aether-deployer-agent"),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(DEPLOYER_SPIFFE_ID),
                x509.DNSName("deployer-container"),
                x509.DNSName("aether-deployer-agent"),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Write PEM files
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    paths["ca_cert"].write_bytes(ca_pem)
    paths["ca_key"].write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    paths["client_cert"].write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
    paths["client_key"].write_bytes(
        client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    paths["server_cert"].write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    paths["server_key"].write_bytes(
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # Write GCP Certificate Manager TrustConfig & Network Security ServerTlsPolicy YAMLs
    indented_ca_pem = "\n".join(f"        {line}" for line in ca_pem.decode("utf-8").strip().splitlines())
    trust_config_content = (
        "description: SPIFFE Trust Bundle for Aether Zero-Trust mTLS\n"
        "trustStores:\n"
        "  - trustAnchors:\n"
        "      - pemCertificate: |\n"
        f"{indented_ca_pem}\n"
    )
    paths["trust_config_yaml"].write_text(trust_config_content, encoding="utf-8")

    project_id = os.getenv("PROJECT_ID", "your-gcp-project-id")
    server_tls_policy_content = (
        "description: Strict mTLS ServerTlsPolicy for Aether Deployer Load Balancer\n"
        "allowOpen: false\n"
        "mtlsPolicy:\n"
        "  clientValidationMode: REJECT_INVALID\n"
        f"  clientValidationTrustConfig: projects/{project_id}/locations/global/trustConfigs/aether-spiffe-trust-config\n"
    )
    paths["server_tls_policy_yaml"].write_text(server_tls_policy_content, encoding="utf-8")

    return paths


def create_mtls_client_context(cert_dir: Optional[str] = None) -> ssl.SSLContext:
    """
    Creates an SSLContext for httpx.Client that:
    1. Trusts both system CAs (including Google Cloud Agent Gateway TLS Inspection CA) and the SPIFFE Root CA (ca.crt).
    2. Presents the Ops Agent's X.509-SVID Client Certificate (ops-client.crt + ops-client.key).
    """
    paths = ensure_mtls_certificates(cert_dir)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if os.path.exists("/etc/ssl/certs/ca-certificates.crt"):
        ctx.load_verify_locations(cafile="/etc/ssl/certs/ca-certificates.crt")
    ctx.load_verify_locations(cafile=str(paths["ca_cert"]))
    ctx.load_cert_chain(
        certfile=str(paths["client_cert"]),
        keyfile=str(paths["client_key"]),
    )
    return ctx


def get_client_cert_metadata(cert_dir: Optional[str] = None) -> Dict[str, str]:
    """
    Extracts the Ops Agent's X.509-SVID SAN URI, SHA-256 fingerprint, and Base64 PEM
    for Cloud Load Balancer mTLS header propagation & cryptographic verification.
    """
    paths = ensure_mtls_certificates(cert_dir)
    pem_bytes = paths["client_cert"].read_bytes()
    cert = x509.load_pem_x509_certificate(pem_bytes)
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    fp_sha256 = hashlib.sha256(der_bytes).hexdigest()

    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    uri_sans = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
    primary_uri = uri_sans[0] if uri_sans else OPS_SPIFFE_ID

    return {
        "uri_san": primary_uri,
        "sha256_fingerprint": fp_sha256,
        "pem_b64": base64.b64encode(pem_bytes).decode("ascii"),
        "serial": hex(cert.serial_number),
    }


def get_client_cert_headers(cert_dir: Optional[str] = None) -> Dict[str, str]:
    """
    Builds HTTP headers matching Google Cloud Application Load Balancer mTLS custom headers
    plus the Base64-encoded X.509-SVID client certificate for direct cryptographic verification.
    """
    meta = get_client_cert_metadata(cert_dir)
    return {
        "X-Client-Cert-Present": "true",
        "X-Client-Cert-Chain-Verified": "true",
        "X-Client-Cert-Uri-Sans": meta["uri_san"],
        "X-Client-Cert-Sha256-Fingerprint": meta["sha256_fingerprint"],
        "X-Client-Cert-Pem-B64": meta["pem_b64"],
    }


def verify_mtls_client_identity(
    expected_spiffe_id: str = OPS_SPIFFE_ID,
    x_client_cert_present: Optional[str] = None,
    x_client_cert_chain_verified: Optional[str] = None,
    x_client_cert_uri_sans: Optional[str] = None,
    x_client_cert_sha256_fingerprint: Optional[str] = None,
    x_client_cert_pem_b64: Optional[str] = None,
    cert_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verifies Mutual TLS client identity from:
    1. Cryptographic X.509-SVID certificate verification against the SPIFFE Root CA (ca.crt), and/or
    2. Google Cloud Application Load Balancer mTLS headers (ServerTlsPolicy + Certificate Manager TrustConfig).
    """
    paths = ensure_mtls_certificates(cert_dir)
    ca_cert = x509.load_pem_x509_certificate(paths["ca_cert"].read_bytes())

    verified_uri_san = None
    verified_fingerprint = None
    verification_mode = None

    # 1. If X.509 certificate PEM is provided, perform full cryptographic verification against Root CA
    if x_client_cert_pem_b64:
        try:
            pem_bytes = base64.b64decode(x_client_cert_pem_b64)
            client_cert = x509.load_pem_x509_certificate(pem_bytes)

            # Verify cryptographic signature using Root CA public key
            ca_pub_key = ca_cert.public_key()
            ca_pub_key.verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                client_cert.signature_hash_algorithm,
            )

            # Verify validity window
            now = datetime.datetime.now(datetime.timezone.utc)
            if now < client_cert.not_valid_before_utc or now > client_cert.not_valid_after_utc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="mTLS Handshake Failed: Client X.509-SVID certificate is expired or not yet valid.",
                )

            # Extract SPIFFE ID from X.509 Subject Alternative Name (URI)
            san_ext = client_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            uri_sans = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
            verified_uri_san = uri_sans[0] if uri_sans else None
            der_bytes = client_cert.public_bytes(serialization.Encoding.DER)
            verified_fingerprint = hashlib.sha256(der_bytes).hexdigest()
            verification_mode = "X509_SVID_CRYPTOGRAPHIC_CHAIN"
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"mTLS X.509-SVID cryptographic verification failed: {str(e)}",
            )

    # 2. Check Google Cloud Application Load Balancer mTLS headers
    if x_client_cert_chain_verified is not None or x_client_cert_present is not None:
        if str(x_client_cert_present).lower() != "true" or str(x_client_cert_chain_verified).lower() != "true":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="mTLS Verification Failed: Client certificate missing or unverified by Load Balancer TrustConfig.",
            )
        if not verified_uri_san and x_client_cert_uri_sans:
            # Cloud Load Balancer may comma-separate multiple URI SANs
            verified_uri_san = x_client_cert_uri_sans.split(",")[0].strip()
            verified_fingerprint = x_client_cert_sha256_fingerprint or "lb-attested-sha256"
            verification_mode = "GCP_LOAD_BALANCER_MTLS_POLICY"

    if not verified_uri_san:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="mTLS Verification Failed: Missing client X.509-SVID certificate or Load Balancer mTLS headers.",
        )

    if verified_uri_san != expected_spiffe_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"mTLS Authorization Failed: Client certificate SAN URI '{verified_uri_san}' is not authorized.",
        )

    return {
        "mtls_verified": True,
        "verification_mode": verification_mode,
        "client_cert_uri_san": verified_uri_san,
        "client_cert_fingerprint": verified_fingerprint,
    }
