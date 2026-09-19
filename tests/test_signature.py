import pytest
from identity_manager.certificate_manager import CertificateManager
from identity_manager.signature_manager import SignatureManager

def test_digital_signature_sign_and_verify():
    cm = CertificateManager()
    cert_pem, priv_pem, _ = cm.issue_agent_certificate("AGENT-TEST-002", "SignerAgent")

    payload = {"request_id": "REQ-101", "amount": 5000}
    sig = SignatureManager.sign_request(payload, priv_pem)

    pub_key_pem = cm._generate_root_ca_certificate()  # Extract public key
    pub_key_pem = cm.ca_private_key.public_key()
    from identity_manager.key_manager import KeyManager
    pub_pem = KeyManager.public_key_to_pem(KeyManager.pem_to_private_key(priv_pem).public_key())

    valid = SignatureManager.verify_signature(payload, sig, pub_pem)
    assert valid is True

    # Modified payload check
    payload_tampered = {"request_id": "REQ-101", "amount": 50000}
    assert SignatureManager.verify_signature(payload_tampered, sig, pub_pem) is False
