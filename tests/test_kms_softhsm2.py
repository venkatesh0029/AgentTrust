import base64
import unittest
import rsa

from identity_manager.kms import KMSProvider


class TestSoftHSM2Integration(unittest.TestCase):
    """Test suite for SoftHSM2 / PKCS#11 key lifecycle, cryptographic isolation, and failure resilience."""

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

    def test_hsm_payload_signing_and_independent_verification(self):
        pub_pem, hsm_handle = self.kms.generate_agent_keypair(self.test_agent_id, key_size=2048)
        payload_bytes = b"Canonical-JSON-Payload-For-PKCS11-Test"
        sig_b64 = self.kms.sign_payload_in_hsm(self.test_agent_id, payload_bytes)
        self.assertIsNotNone(sig_b64)
        self.assertGreater(len(sig_b64), 50)

        # Independent signature verification using public key PEM
        sig_bytes = base64.b64decode(sig_b64)
        pub_key_obj = rsa.PublicKey.load_pkcs1(pub_pem.encode('utf-8'))
        verify_result = rsa.verify(payload_bytes, sig_bytes, pub_key_obj)
        self.assertEqual(verify_result, 'SHA-256')

    def test_safe_failure_on_invalid_agent_or_missing_token(self):
        """Verifies fail-closed behavior when signing with non-existent agent key handle."""
        with self.assertRaises(ValueError) as ctx:
            self.kms.sign_payload_in_hsm("UNREGISTERED_AGENT_999", b"payload")
        self.assertIn("not found in KMS metadata vault", str(ctx.exception))

    def test_explicit_pkcs11_mode_fail_closed(self):
        """Verifies explicit REAL_SOFT_HSM2_PKCS11 mode raises RuntimeError if token is missing."""
        status = self.kms.get_provider_status()
        if not status["is_token_backed"]:
            with self.assertRaises(RuntimeError) as ctx:
                KMSProvider(provider_type="REAL_SOFT_HSM2_PKCS11")
            self.assertIn("Explicitly requested REAL_SOFT_HSM2_PKCS11 mode", str(ctx.exception))

    def test_hsm_key_rotation(self):
        pub_1, handle_1 = self.kms.generate_agent_keypair(self.test_agent_id, key_size=2048)
        pub_2, handle_2, version_2 = self.kms.rotate_agent_key(self.test_agent_id)
        self.assertEqual(version_2, 2)
        self.assertNotEqual(pub_1, pub_2)


if __name__ == "__main__":
    unittest.main()
