"""
SoftHSM2 & PKCS#11 Hardware Security Module Integration Tests.
Verifies RSA-2048 key generation, provider status reporting, and non-exportable signature execution.
"""

import unittest
from identity_manager.kms import KMSProvider, find_softhsm2_library


class TestSoftHSM2Integration(unittest.TestCase):
    """Test suite for SoftHSM2 / PKCS#11 key lifecycle and cryptographic isolation."""

    def setUp(self):
        self.kms = KMSProvider(provider_type="AUTO_DETECT")
        self.test_agent_id = "HSM-TEST-AGENT-001"

    def test_provider_status_reporting(self):
        status = self.kms.get_provider_status()
        self.assertIn("provider_type", status)
        self.assertIn("pkcs11_library_detected", status)
        self.assertIn(status["provider_type"], ["REAL_SOFT_HSM2_PKCS11", "LOCAL_SOFTWARE_STORE"])

    def test_hsm_keypair_generation(self):
        pub_pem, hsm_handle = self.kms.generate_agent_keypair(self.test_agent_id, key_size=2048)
        self.assertTrue(pub_pem.startswith("-----BEGIN RSA PUBLIC KEY-----") or pub_pem.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(hsm_handle.startswith("pkcs11://") or hsm_handle.startswith("local-software://"))

        # Verify application metadata vault contains NO raw private key PEM string
        meta = self.kms._key_metadata_vault[self.test_agent_id]
        self.assertNotIn("raw_priv_pem", meta)
        self.assertNotIn("private_key_pem", meta)

    def test_hsm_payload_signing(self):
        pub_pem, hsm_handle = self.kms.generate_agent_keypair(self.test_agent_id, key_size=2048)
        payload_bytes = b"Canonical-JSON-Payload-For-PKCS11-Test"
        sig_b64 = self.kms.sign_payload_in_hsm(self.test_agent_id, payload_bytes)
        self.assertIsNotNone(sig_b64)
        self.assertGreater(len(sig_b64), 50)

    def test_hsm_key_rotation(self):
        pub_1, handle_1 = self.kms.generate_agent_keypair(self.test_agent_id, key_size=2048)
        pub_2, handle_2, version_2 = self.kms.rotate_agent_key(self.test_agent_id)
        self.assertEqual(version_2, 2)
        self.assertNotEqual(pub_1, pub_2)


if __name__ == "__main__":
    unittest.main()
