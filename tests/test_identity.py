import pytest
from identity_manager.certificate_manager import CertificateManager
from identity_manager.key_manager import KeyManager

def test_root_ca_and_cert_issuance():
    cm = CertificateManager(ca_common_name="Test CA")
    cert_pem, priv_pem, fp = cm.issue_agent_certificate("AGENT-TEST-001", "TestAgent")

    assert "BEGIN CERTIFICATE" in cert_pem
    assert "BEGIN PRIVATE KEY" in priv_pem
    assert fp.startswith("SHA256:")

    val_res = cm.verify_agent_certificate(cert_pem)
    assert val_res["valid"] is True
    assert val_res["agent_id"] == "AGENT-TEST-001"
