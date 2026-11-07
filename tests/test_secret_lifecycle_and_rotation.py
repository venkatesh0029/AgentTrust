"""
Comprehensive Acceptance and Security Test Suite for Work Package #3:
Centralized Secret Lifecycle & Rotation Management.

Verifies all 12 criteria specified in WP-3:
1. Secret survives server restart
2. Multiple workers load identical active secret
3. Missing production secret fails closed
4. V1 accepted during grace period
5. V1 rejected after grace period
6. V2 accepted after rotation
7. Emergency revocation immediately invalidates credentials
8. Concurrent rotation attempts are atomic without inconsistent state
9. Corrupted store or unavailable provider fails closed
10. Raw secrets are absent from logs and metadata representations (***REDACTED***)
11. Stale worker cache cannot accept expired/revoked secret
12. Unauthorized rotation/revocation requests return 401/403 (RBAC enforced)
"""

import concurrent.futures
import datetime
import os
import shutil
import tempfile
import time

import pytest
from fastapi.testclient import TestClient

from identity_manager.jwt_auth import JWTAuthManager
from protected_api.finance_api import ProtectedFinanceAPI
from secret_manager.secret_models import SecretRecord
from secret_manager.secret_provider import (
    PersistentEncryptedSecretProvider,
    ProductionConfigurationError,
    get_centralized_secret_provider,
)
from server import app, validate_production_configuration


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="agenttrust_secret_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


class TestSecretLifecycleAndRotation:
    """Automated security verification for WP-3."""

    def test_01_secret_survives_server_restart(self, temp_dir):
        """
        Criterion 1: Secret survives server restart.
        Ensures active credentials persist across process restarts without alteration.
        """
        store_path = os.path.join(temp_dir, "gateway_secrets.enc")
        passphrase = "master_test_passphrase_32_chars_long!!"

        # 1. Initialize server v1
        provider_v1 = PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase=passphrase,
            initial_secret="v1_durable_gateway_secret_value_2026",
            is_production=True
        )
        v1_active = provider_v1.get_active_secret()
        assert v1_active.version == 1
        assert v1_active.secret_value == "v1_durable_gateway_secret_value_2026"
        assert v1_active.status == "ACTIVE"
        key_id_v1 = v1_active.key_id

        # 2. Simulate server termination and restart (fresh instance from persisted file)
        del provider_v1
        provider_v2 = PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase=passphrase,
            is_production=True
        )
        restarted_active = provider_v2.get_active_secret()
        assert restarted_active.key_id == key_id_v1
        assert restarted_active.version == 1
        assert restarted_active.secret_value == "v1_durable_gateway_secret_value_2026"
        assert restarted_active.status == "ACTIVE"

    def test_02_multiple_workers_load_identical_active_secret(self, temp_dir):
        """
        Criterion 2: Multiple workers load identical active secret.
        Ensures consistent gateway credentials across worker processes.
        """
        store_path = os.path.join(temp_dir, "shared_secrets.enc")
        passphrase = "shared_multiworker_master_key_999!!"

        # Pre-seed persistent provider
        master_provider = PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase=passphrase,
            initial_secret="shared_worker_auth_token_7777",
            is_production=True
        )
        expected_key_id = master_provider.get_active_secret().key_id

        # Simulate 4 independent worker instances
        worker_1 = PersistentEncryptedSecretProvider(store_path, passphrase, is_production=True)
        worker_2 = PersistentEncryptedSecretProvider(store_path, passphrase, is_production=True)
        worker_3 = PersistentEncryptedSecretProvider(store_path, passphrase, is_production=True)
        background_worker = PersistentEncryptedSecretProvider(store_path, passphrase, is_production=True)

        for w in (worker_1, worker_2, worker_3, background_worker):
            sec = w.get_active_secret()
            assert sec.key_id == expected_key_id
            assert sec.secret_value == "shared_worker_auth_token_7777"
            assert sec.version == 1
            assert sec.status == "ACTIVE"

    def test_03_missing_production_secret_fails_closed(self, temp_dir):
        """
        Criterion 3: Missing production secret.
        Production must refuse startup when configuration is missing or insecure.
        """
        # A. Missing secret and missing store
        with pytest.raises(ProductionConfigurationError) as exc_info:
            get_centralized_secret_provider(
                env_profile="production",
                storage_path=os.path.join(temp_dir, "nonexistent.enc"),
                explicit_secret=None
            )
        assert "FAIL-CLOSED" in str(exc_info.value)

        # B. Default insecure secret in production
        with pytest.raises(ProductionConfigurationError):
            get_centralized_secret_provider(
                env_profile="production",
                storage_path=os.path.join(temp_dir, "nonexistent.enc"),
                explicit_secret="default_secret_key_change_in_production"
            )

        # C. Server validate_production_configuration rejects missing secret
        old_env = os.environ.get("GATEWAY_SECRET")
        old_store = os.environ.get("AGENTTRUST_SECRET_STORE_PATH")
        try:
            os.environ.pop("GATEWAY_SECRET", None)
            os.environ.pop("AGENTTRUST_SECRET_STORE_PATH", None)
            with pytest.raises((ProductionConfigurationError, RuntimeError)):
                validate_production_configuration("production", "MODE_D_AGENTTRUST_FABRIC")
        finally:
            if old_env:
                os.environ["GATEWAY_SECRET"] = old_env
            if old_store:
                os.environ["AGENTTRUST_SECRET_STORE_PATH"] = old_store

    def test_04_v1_accepted_during_grace_period(self, temp_dir):
        """
        Criterion 4: V1 accepted during grace period.
        Zero-downtime rotation permits in-flight callers with previous credentials.
        """
        store_path = os.path.join(temp_dir, "grace_secrets.enc")
        passphrase = "test_grace_period_passphrase_123!!"
        provider = PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase=passphrase,
            initial_secret="v1_initial_secret_token_111"
        )
        finance_api = ProtectedFinanceAPI(secret_provider=provider)

        v1_val = provider.get_active_secret().secret_value
        # Rotate secret with 60s grace period
        v2_rec = provider.rotate_secret(new_secret="v2_rotated_secret_token_222", grace_period_seconds=60)
        assert v2_rec.version == 2

        # Validate V1 - must be valid as previous credential within grace period
        res_v1 = provider.validate_secret(v1_val)
        assert res_v1.is_valid is True
        assert res_v1.is_previous is True
        assert res_v1.version == 1
        assert res_v1.error is None

        # Execute finance action using V1 credential during grace period
        auth_headers = finance_api.create_gateway_auth_headers("REQ-TEST-GRACE-V1")
        outcome = finance_api.execute_action(
            action="CREATE_PURCHASE_ORDER",
            parameters={"supplier_id": "SUP-GRACE", "amount": 2500.0},
            gateway_token=v1_val,
            request_id="REQ-TEST-GRACE-V1",
            agent_id="FINANCE-AGENT-001",
            auth_headers=auth_headers
        )
        assert outcome["success"] is True

    def test_05_v1_rejected_after_grace_period(self, temp_dir):
        """
        Criterion 5: V1 rejected after grace period expiration.
        Once the grace period deadline lapses, previous credentials return 401/denied.
        """
        store_path = os.path.join(temp_dir, "exp_secrets.enc")
        passphrase = "test_expiration_passphrase_456!!"
        provider = PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase=passphrase,
            initial_secret="v1_to_expire_secret_999"
        )
        finance_api = ProtectedFinanceAPI(secret_provider=provider)
        v1_val = provider.get_active_secret().secret_value

        # Rotate with 1 second grace period
        provider.rotate_secret(new_secret="v2_fresh_secret_888", grace_period_seconds=1)

        # Sleep to exceed grace period
        time.sleep(1.2)

        # Validate V1 - must be rejected with GRACE_PERIOD_EXPIRED
        res_v1 = provider.validate_secret(v1_val)
        assert res_v1.is_valid is False
        assert res_v1.error == "GRACE_PERIOD_EXPIRED"

        # ProtectedFinanceAPI rejects execution with DIRECT_ACCESS_DENIED
        auth_headers = finance_api.create_gateway_auth_headers("REQ-TEST-EXP-V1")
        outcome = finance_api.execute_action(
            action="CREATE_PURCHASE_ORDER",
            parameters={"supplier_id": "SUP-EXP", "amount": 2500.0},
            gateway_token=v1_val,
            request_id="REQ-TEST-EXP-V1",
            agent_id="FINANCE-AGENT-001",
            auth_headers=auth_headers
        )
        assert outcome["success"] is False
        assert outcome["error"] == "DIRECT_ACCESS_DENIED"
        assert "GRACE_PERIOD_EXPIRED" in outcome["message"]

    def test_06_v2_accepted_after_rotation(self, temp_dir):
        """
        Criterion 6: V2 accepted after rotation.
        New active secret immediately valid across all operations.
        """
        store_path = os.path.join(temp_dir, "v2_secrets.enc")
        passphrase = "test_v2_rotation_passphrase_789!!"
        provider = PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase=passphrase,
            initial_secret="v1_old_secret_value"
        )
        finance_api = ProtectedFinanceAPI(secret_provider=provider)

        v2_rec = provider.rotate_secret(new_secret="v2_active_brand_new_secret", grace_period_seconds=3600)
        assert v2_rec.status == "ACTIVE"
        assert v2_rec.version == 2

        # Validate V2 candidate
        res_v2 = provider.validate_secret("v2_active_brand_new_secret")
        assert res_v2.is_valid is True
        assert res_v2.is_previous is False
        assert res_v2.version == 2

        # Execute finance action using V2 credential
        auth_headers = finance_api.create_gateway_auth_headers("REQ-TEST-V2-ACTIVE")
        outcome = finance_api.execute_action(
            action="CREATE_PURCHASE_ORDER",
            parameters={"supplier_id": "SUP-V2", "amount": 1000.0},
            gateway_token="v2_active_brand_new_secret",
            request_id="REQ-TEST-V2-ACTIVE",
            agent_id="FINANCE-AGENT-001",
            auth_headers=auth_headers
        )
        assert outcome["success"] is True

    def test_07_emergency_revocation(self, temp_dir):
        """
        Criterion 7: Emergency revocation.
        Immediately invalidates compromised secret versions, even within active grace period.
        """
        store_path = os.path.join(temp_dir, "revoke_secrets.enc")
        passphrase = "test_revoke_passphrase_321!!"
        provider = PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase=passphrase,
            initial_secret="v1_compromised_credential_val"
        )
        finance_api = ProtectedFinanceAPI(secret_provider=provider)

        v1_rec = provider.get_active_secret()
        key_id_v1 = v1_rec.key_id
        v1_val = v1_rec.secret_value

        # Rotate with 1 hour grace period
        provider.rotate_secret(new_secret="v2_clean_secret_credential", grace_period_seconds=3600)

        # Before revocation: V1 is accepted during grace period
        assert provider.validate_secret(v1_val).is_valid is True

        # Perform emergency revocation on V1
        revocation_success = provider.revoke_secret(key_id_v1, reason="SUSPECTED_KEY_LEAK_CVE_2026")
        assert revocation_success is True

        # After emergency revocation: V1 is rejected immediately
        res_revoked = provider.validate_secret(v1_val)
        assert res_revoked.is_valid is False
        assert res_revoked.error == "SECRET_REVOKED"

        # Finance API rejects execution immediately
        auth_headers = finance_api.create_gateway_auth_headers("REQ-TEST-REVOKED-V1")
        outcome = finance_api.execute_action(
            action="CREATE_PURCHASE_ORDER",
            parameters={"supplier_id": "SUP-REVOKED", "amount": 500.0},
            gateway_token=v1_val,
            request_id="REQ-TEST-REVOKED-V1",
            agent_id="FINANCE-AGENT-001",
            auth_headers=auth_headers
        )
        assert outcome["success"] is False
        assert outcome["error"] == "DIRECT_ACCESS_DENIED"
        assert "SECRET_REVOKED" in outcome["message"]

    def test_08_concurrent_rotation_attempts_are_atomic(self, temp_dir):
        """
        Criterion 8: Concurrent rotation attempts.
        Multiple threads/workers rotating simultaneously must remain consistent with no corrupted state.
        """
        store_path = os.path.join(temp_dir, "concurrent_secrets.enc")
        passphrase = "concurrent_rotation_passphrase_999!!"
        # Initialize
        PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase=passphrase,
            initial_secret="init_seed_secret"
        )

        num_rotations = 8

        def do_rotation(worker_idx: int):
            worker = PersistentEncryptedSecretProvider(store_path, passphrase)
            return worker.rotate_secret(
                new_secret=f"concurrent_secret_worker_{worker_idx}",
                grace_period_seconds=3600
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(do_rotation, i) for i in range(num_rotations)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == num_rotations

        # Verify final state on a clean provider instance
        verifier = PersistentEncryptedSecretProvider(store_path, passphrase)
        meta = verifier.get_metadata()
        # All rotations occurred cleanly: version counter must equal initial (1) + num_rotations
        assert meta["current_version"] == 1 + num_rotations
        assert meta["total_versions"] == 1 + num_rotations
        active_rec = verifier.get_active_secret()
        assert active_rec.status == "ACTIVE"

    def test_09_provider_unavailable_or_corrupted_fails_closed(self, temp_dir):
        """
        Criterion 9: Provider unavailable / corrupted store.
        System must fail closed rather than falling back to an unauthenticated or random state.
        """
        store_path = os.path.join(temp_dir, "corrupt_secrets.enc")
        passphrase = "valid_passphrase_32_characters!!"
        PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase=passphrase,
            initial_secret="valid_v1_secret"
        )

        # 1. Corrupt the file payload
        with open(store_path, "wb") as f:
            f.write(b"CORRUPTED_CIPHERTEXT_RANDOM_GARBAGE_BYTES_1234567890")

        # Must fail closed with ProductionConfigurationError or RuntimeError
        with pytest.raises((ProductionConfigurationError, RuntimeError)):
            PersistentEncryptedSecretProvider(store_path, passphrase, is_production=True)

        # 2. Wrong master key passphrase fails closed
        with pytest.raises(ProductionConfigurationError):
            PersistentEncryptedSecretProvider(store_path, "WRONG_PASSPHRASE_XYZ", is_production=True)

    def test_10_raw_secrets_absent_from_logs_and_metadata(self, temp_dir):
        """
        Criterion 10: Raw secrets absent from logs.
        Repr, str, to_metadata, and API status dicts must NEVER expose plaintext secret values.
        """
        secret_plaintext = "SUPER_SENSITIVE_CRYPTOGRAPHIC_KEY_VALUE_XYZ_999"
        rec = SecretRecord(
            key_id="gw-sec-v1-abc",
            version=1,
            secret_value=secret_plaintext,
            status="ACTIVE",
            created_at=datetime.datetime.now(datetime.UTC).isoformat()
        )

        # 1. str() and repr() redact secret_value
        rec_repr = repr(rec)
        rec_str = str(rec)
        assert secret_plaintext not in rec_repr
        assert secret_plaintext not in rec_str
        assert "***REDACTED***" in rec_repr
        assert "***REDACTED***" in rec_str

        # 2. to_metadata() omits secret_value entirely
        meta = rec.to_metadata()
        assert "secret_value" not in meta
        assert secret_plaintext not in str(meta)

        # 3. Provider get_metadata() contains no plaintext secrets
        store_path = os.path.join(temp_dir, "redact_test.enc")
        provider = PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase="passphrase_redaction_123!!",
            initial_secret=secret_plaintext
        )
        provider_meta = provider.get_metadata()
        assert secret_plaintext not in str(provider_meta)
        for s in provider_meta["secrets"]:
            assert "secret_value" not in s

    def test_11_stale_worker_cache_cannot_accept_expired_or_revoked_secret(self, temp_dir):
        """
        Criterion 11: Stale worker cache.
        When Worker B rotates or revokes a secret on the shared storage, Worker A's cache
        automatically refreshes and cannot accept the expired or revoked secret.
        """
        store_path = os.path.join(temp_dir, "stale_cache.enc")
        passphrase = "stale_cache_test_passphrase_777!!"

        worker_a = PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase=passphrase,
            initial_secret="shared_v1_initial_token"
        )
        worker_b = PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase=passphrase
        )

        v1_val = worker_a.get_active_secret().secret_value
        key_id_v1 = worker_a.get_active_secret().key_id

        # Worker B revokes V1 directly on disk
        worker_b.revoke_secret(key_id_v1, reason="EMERGENCY_REVOKE_ON_WORKER_B")

        # Worker A attempts to validate V1: disk mtime triggers auto-reload, invalidating cache
        res = worker_a.validate_secret(v1_val)
        assert res.is_valid is False
        assert res.error == "SECRET_REVOKED"

    def test_12_unauthorized_rotation_request_returns_401_or_403(self):
        """
        Criterion 12: Unauthorized rotation request.
        Management endpoints reject unauthenticated or under-privileged callers with 401/403.
        """
        client = TestClient(app)

        # 1. Unauthenticated request -> 401
        res_unauth = client.post("/identity/gateway-secret/rotate", json={"grace_period_seconds": 3600})
        assert res_unauth.status_code == 401

        # 2. Forbidden: POLICY_ADMIN or AUDITOR role lacks 'manage_secrets' permission -> 403
        auditor_token = JWTAuthManager.create_admin_token(role="AUDITOR", identity_id="auditor_test")
        res_forbidden = client.post(
            "/identity/gateway-secret/rotate",
            headers={"Authorization": f"Bearer {auditor_token}"},
            json={"grace_period_seconds": 3600}
        )
        assert res_forbidden.status_code == 403
        assert "RBAC Denial" in res_forbidden.json()["detail"]

        # 3. Authorized: SYSTEM_ADMIN succeeds -> 200
        admin_token = JWTAuthManager.create_admin_token(role="SYSTEM_ADMIN", identity_id="admin_test")
        res_ok = client.post(
            "/identity/gateway-secret/rotate",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"grace_period_seconds": 1800}
        )
        assert res_ok.status_code == 200
        data = res_ok.json()
        assert data["success"] is True
        assert data["active_secret"]["status"] == "ACTIVE"
        assert "secret_value" not in data["active_secret"]  # Redacted!

        # 4. Status endpoint: Accessible to AUDITOR and SYSTEM_ADMIN with safe redacted metadata
        res_status = client.get(
            "/identity/gateway-secret/status",
            headers={"Authorization": f"Bearer {auditor_token}"}
        )
        assert res_status.status_code == 200
        status_data = res_status.json()
        assert "active_key_id" in status_data
        assert "current_version" in status_data
        assert "secrets" in status_data
        assert "secret_value" not in str(status_data)
