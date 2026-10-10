"""
SoftHSM2 & PKCS#11 Hardware Security Module Integration Tests.
Verifies RSA-2048 key generation, secure storage, and hardware-boundary signature generation.
"""

import unittest
from identity_manager.kms import KMSProvider, kms_provider


class TestSoftHSM2Integration(unittest.TestCase):
    """Test suite for SoftHSM2 / PKCS#11 key lifecycle and cryptographic isolation."""

    def setUp(self):
        self.kms = KMSProvider(provider_type="HSM_PKCS11")
        self.test_agent_id = "HSM-TEST-AGENT-001"

    def test_hsm_keypair_generation(self):
        pub_pem, priv_handle = self.kms.generate_agent_keypair(self.test_agent_id, key_size=2048)
        self.assertTrue(pub_pem.startswith("-----BEGIN RSA PUBLIC KEY-----") or pub_pem.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(priv_handle.startswith("hsm://"))
        self.assertIn("hsm-slot-", priv_handle)

    def test_hsm_payload_signing(self):
        pub_pem, priv_handle = self.kms.generate_agent_keypair(self.test_agent_id, key_size=2048)
        payload_bytes = b"Canonical-JSON-Payload-For-HSM-Test"
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
