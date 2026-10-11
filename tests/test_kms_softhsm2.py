import base64
import os
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

    def test_hsm_non_extractability_and_hardware_isolation(self):
        """Validates that keys generated in the HSM have CKA_EXTRACTABLE=FALSE and CKA_SENSITIVE=TRUE."""
        if not self.kms.get_provider_status()["is_token_backed"]:
            self.skipTest("SoftHSM2 token is not available")
        import pkcs11
        from pkcs11 import Attribute

        pub_pem, hsm_handle = self.kms.generate_agent_keypair("EXTRACT-TEST-AGENT", key_size=2048)
        meta = self.kms._key_metadata_vault["EXTRACT-TEST-AGENT"]
        key_id = meta["pkcs11_key_id"]

        session = self.kms._pkcs11_session
        assert session is not None
        priv_key = session.get_key(object_class=pkcs11.ObjectClass.PRIVATE_KEY, id=key_id)

        # Assert non-extractability security attributes
        self.assertFalse(priv_key[Attribute.EXTRACTABLE], "CKA_EXTRACTABLE must be False")
        self.assertTrue(priv_key[Attribute.SENSITIVE], "CKA_SENSITIVE must be True")

        # Hardware-enforced export prevention: reading raw private value raises exception
        with self.assertRaises(Exception):
            _ = priv_key[Attribute.VALUE]

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

    def test_hsm_signature_persistence_across_restarts(self):
        """Verifies that generated keys persist in the token across provider instances/restarts."""
        if not self.kms.get_provider_status()["is_token_backed"]:
            self.skipTest("SoftHSM2 token is not available")
        import pkcs11
        from pkcs11 import Mechanism

        pub_pem, hsm_handle = self.kms.generate_agent_keypair("PERSIST-AGENT-01", key_size=2048)
        key_id = self.kms._key_metadata_vault["PERSIST-AGENT-01"]["pkcs11_key_id"]

        # Simulate fresh application startup with separate session
        kms_fresh = KMSProvider(provider_type="REAL_SOFT_HSM2_PKCS11")
        session2 = kms_fresh._pkcs11_session
        self.assertIsNotNone(session2)
        assert session2 is not None

        # Retrieve persistent key by key_id directly from the token
        priv2 = session2.get_key(object_class=pkcs11.ObjectClass.PRIVATE_KEY, id=key_id)
        self.assertIsNotNone(priv2)

        test_payload = b"Payload-Across-Application-Restart"
        sig_raw = priv2.sign(test_payload, mechanism=Mechanism.SHA256_RSA_PKCS)

        # Verify signature using previously exported public key
        pub_key_obj = rsa.PublicKey.load_pkcs1(pub_pem.encode('utf-8'))
        verify_result = rsa.verify(test_payload, sig_raw, pub_key_obj)
        self.assertEqual(verify_result, 'SHA-256')

    def test_explicit_pkcs11_mode_operational(self):
        """Verifies that requesting REAL_SOFT_HSM2_PKCS11 succeeds when token is available."""
        if not self.kms.get_provider_status()["is_token_backed"]:
            self.skipTest("SoftHSM2 token is not available")
        kms_real = KMSProvider(provider_type="REAL_SOFT_HSM2_PKCS11")
        status = kms_real.get_provider_status()
        self.assertEqual(status["provider_type"], "REAL_SOFT_HSM2_PKCS11")
        self.assertTrue(status["is_token_backed"])
        self.assertTrue(status["pkcs11_library_detected"])

    def test_explicit_pkcs11_mode_fail_closed(self):
        """Verifies explicit REAL_SOFT_HSM2_PKCS11 mode raises RuntimeError if token is missing."""
        old_token = os.environ.get("SOFTHSM2_TOKEN")
        try:
            os.environ["SOFTHSM2_TOKEN"] = "NON_EXISTENT_TOKEN_12345"
            with self.assertRaises(RuntimeError) as ctx:
                KMSProvider(provider_type="REAL_SOFT_HSM2_PKCS11")
            self.assertIn("Explicitly requested REAL_SOFT_HSM2_PKCS11 mode", str(ctx.exception))
        finally:
            if old_token is not None:
                os.environ["SOFTHSM2_TOKEN"] = old_token
            else:
                os.environ.pop("SOFTHSM2_TOKEN", None)

    def test_safe_failure_on_invalid_agent_or_missing_token(self):
        """Verifies fail-closed behavior when signing with non-existent agent key handle."""
        with self.assertRaises(ValueError) as ctx:
            self.kms.sign_payload_in_hsm("UNREGISTERED_AGENT_999", b"payload")
        self.assertIn("not found in KMS metadata vault", str(ctx.exception))

    def test_hsm_key_rotation(self):
        pub_1, handle_1 = self.kms.generate_agent_keypair(self.test_agent_id, key_size=2048)
        pub_2, handle_2, version_2 = self.kms.rotate_agent_key(self.test_agent_id)
        self.assertEqual(version_2, 2)
        self.assertNotEqual(pub_1, pub_2)


if __name__ == "__main__":
    unittest.main()
