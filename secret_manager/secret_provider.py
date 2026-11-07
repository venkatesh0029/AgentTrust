"""
Centralized Secret Provider Interface, Lifecycle Management, and Storage Engines.

Supports:
1. Multi-worker and multi-process secret consistency across application restarts.
2. Zero-downtime secret rotation with configurable grace-period expiration.
3. Constant-time secret verification (hmac.compare_digest) to prevent timing attacks.
4. Immediate emergency revocation of compromised credentials.
5. Authenticated AES-256-GCM encryption at rest for persistent storage.
6. Fail-closed production enforcement (missing/invalid production configuration aborts startup).
"""

import abc
import datetime
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secret_manager.secret_models import SecretRecord, ValidationResult


class ProductionConfigurationError(RuntimeError):
    """Raised when production secret configuration is missing, default, or unsafe."""
    pass


class CrossProcessLock:
    """Cross-platform advisory file lock for atomic multi-worker secret rotation."""

    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self._file = None

    def __enter__(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.lock_path)), exist_ok=True)
        self._file = open(self.lock_path, "a+")
        if os.name == "nt":
            import msvcrt
            # Attempt non-blocking lock with backoff
            for _ in range(50):
                try:
                    self._file.seek(0)
                    msvcrt.locking(self._file.fileno(), msvcrt.LK_NBLCK, 1)
                    return self
                except OSError:
                    time.sleep(0.05)
            # Blocking fallback
            self._file.seek(0)
            msvcrt.locking(self._file.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file:
            try:
                if os.name == "nt":
                    import msvcrt
                    self._file.seek(0)
                    msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            finally:
                self._file.close()
                self._file = None


class SecretProvider(abc.ABC):
    """Abstract Base Class for Centralized Gateway Secret Management."""

    @abc.abstractmethod
    def get_active_secret(self) -> SecretRecord:
        """Returns the current active SecretRecord."""
        pass

    @abc.abstractmethod
    def validate_secret(self, candidate_secret: str) -> ValidationResult:
        """Validates candidate secret against active and permitted previous versions in constant time."""
        pass

    @abc.abstractmethod
    def rotate_secret(self, new_secret: str | None = None, grace_period_seconds: int = 3600) -> SecretRecord:
        """Atomically rotates secret, setting old active to previous with grace period."""
        pass

    @abc.abstractmethod
    def revoke_secret(self, key_id: str, reason: str = "EMERGENCY_REVOCATION") -> bool:
        """Immediately revokes a secret version, invalidating it even within grace period."""
        pass

    @abc.abstractmethod
    def get_metadata(self) -> dict[str, Any]:
        """Returns safe, redacted metadata for auditing and health checks."""
        pass


class PersistentEncryptedSecretProvider(SecretProvider):
    """
    Production-grade Centralized Secret Provider.
    Persists secret bundle encrypted at rest using AES-256-GCM.
    Enforces atomic multi-worker synchronization via advisory file locking and mtime cache invalidation.
    """

    def __init__(
        self,
        storage_path: str,
        encryption_passphrase: str | None = None,
        initial_secret: str | None = None,
        is_production: bool = False
    ):
        self.storage_path = os.path.abspath(storage_path)
        self.lock_path = f"{self.storage_path}.lock"
        self.is_production = is_production

        passphrase = (
            encryption_passphrase
            or os.environ.get("AGENTTRUST_MASTER_KEY")
            or os.environ.get("KEY_STORAGE_PASSPHRASE")
            or ("agenttrust_dev_master_key_2026_xyz" if not is_production else None)
        )
        if not passphrase:
            raise ProductionConfigurationError(
                "FAIL-CLOSED: Production requires explicit AGENTTRUST_MASTER_KEY or encryption passphrase."
            )

        # Derive 256-bit AES key via SHA-256
        self._aes_key = hashlib.sha256(passphrase.encode("utf-8")).digest()
        self._lock = threading.Lock()
        self._last_mtime: float = -1.0

        self._active_key_id: str = ""
        self._version_counter: int = 0
        self._secrets: dict[str, SecretRecord] = {}
        self._revoked_key_ids: set[str] = set()

        # Initialize or load existing store
        with CrossProcessLock(self.lock_path):
            if os.path.exists(self.storage_path):
                self._load_from_disk()
            else:
                if self.is_production and not initial_secret:
                    # In production, missing store without initial secret fails closed
                    raise ProductionConfigurationError(
                        "FAIL-CLOSED: Production secret store not found and no initial secret configured."
                    )
                sec_val = initial_secret or secrets.token_hex(32)
                self._init_fresh_store(sec_val)

    def _init_fresh_store(self, initial_secret_value: str) -> None:
        """Initializes V1 secret record and persists encrypted bundle to disk."""
        now_iso = datetime.datetime.now(datetime.UTC).isoformat()
        key_id = f"gw-sec-v1-{secrets.token_hex(4)}"
        rec = SecretRecord(
            key_id=key_id,
            version=1,
            secret_value=initial_secret_value,
            status="ACTIVE",
            created_at=now_iso
        )
        self._active_key_id = key_id
        self._version_counter = 1
        self._secrets = {key_id: rec}
        self._revoked_key_ids = set()
        self._save_to_disk()

    def _save_to_disk(self) -> None:
        """Serializes and encrypts secret bundle using AES-256-GCM, writing atomically."""
        raw_dict = {
            "active_key_id": self._active_key_id,
            "version_counter": self._version_counter,
            "secrets": {
                k: {
                    "key_id": v.key_id,
                    "version": v.version,
                    "secret_value": v.secret_value,
                    "status": v.status,
                    "created_at": v.created_at,
                    "expires_at": v.expires_at,
                    "revoked_at": v.revoked_at,
                    "revocation_reason": v.revocation_reason
                }
                for k, v in self._secrets.items()
            },
            "revoked_key_ids": list(self._revoked_key_ids)
        }
        json_bytes = json.dumps(raw_dict, sort_keys=True).encode("utf-8")
        nonce = os.urandom(12)
        aesgcm = AESGCM(self._aes_key)
        ciphertext = aesgcm.encrypt(nonce, json_bytes, None)

        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        tmp_path = f"{self.storage_path}.tmp.{os.getpid()}_{time.time()}"
        with open(tmp_path, "wb") as f:
            f.write(nonce + ciphertext)
            f.flush()
            os.fsync(f.fileno())

        # Atomic replace
        os.replace(tmp_path, self.storage_path)
        self._last_mtime = os.path.getmtime(self.storage_path)

    def _load_from_disk(self) -> None:
        """Reads, decrypts, and rehydrates secret bundle from disk."""
        if not os.path.exists(self.storage_path):
            return
        mtime = os.path.getmtime(self.storage_path)
        if mtime <= self._last_mtime:
            return  # In-memory cache is up to date

        with open(self.storage_path, "rb") as f:
            data = f.read()

        if len(data) < 28:
            raise RuntimeError("Secret store payload corrupted or truncated.")

        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(self._aes_key)
        try:
            json_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise ProductionConfigurationError(
                f"FAIL-CLOSED: Unable to decrypt secret store. Invalid master key or corrupted data: {e}"
            )

        raw_dict = json.loads(json_bytes.decode("utf-8"))
        self._active_key_id = raw_dict["active_key_id"]
        self._version_counter = raw_dict["version_counter"]
        self._revoked_key_ids = set(raw_dict.get("revoked_key_ids", []))

        reloaded_secrets = {}
        for k, v in raw_dict["secrets"].items():
            reloaded_secrets[k] = SecretRecord(
                key_id=v["key_id"],
                version=v["version"],
                secret_value=v["secret_value"],
                status=v["status"],
                created_at=v["created_at"],
                expires_at=v.get("expires_at"),
                revoked_at=v.get("revoked_at"),
                revocation_reason=v.get("revocation_reason")
            )
        self._secrets = reloaded_secrets
        self._last_mtime = mtime

    def _refresh_if_stale(self) -> None:
        """Checks disk mtime and auto-reloads if rotated or revoked by another worker process."""
        if os.path.exists(self.storage_path):
            curr_mtime = os.path.getmtime(self.storage_path)
            if curr_mtime > self._last_mtime:
                with CrossProcessLock(self.lock_path):
                    self._load_from_disk()

    def get_active_secret(self) -> SecretRecord:
        """Returns the active SecretRecord after verifying freshness."""
        with self._lock:
            self._refresh_if_stale()
            active_rec = self._secrets.get(self._active_key_id)
            if not active_rec or active_rec.status != "ACTIVE":
                raise RuntimeError("No active secret configured in secret store.")
            return active_rec

    def validate_secret(self, candidate_secret: str) -> ValidationResult:
        """
        Validates candidate secret in constant time against active and previous versions.
        Enforces grace-period expiration and immediate revocation checks.
        """
        if not candidate_secret or not isinstance(candidate_secret, str):
            return ValidationResult(is_valid=False, error="INVALID_SECRET")

        with self._lock:
            self._refresh_if_stale()
            now_utc = datetime.datetime.now(datetime.UTC)

            # Check active secret first
            active_rec = self._secrets.get(self._active_key_id)
            if active_rec and hmac.compare_digest(candidate_secret, active_rec.secret_value):
                if active_rec.status == "REVOKED" or active_rec.key_id in self._revoked_key_ids:
                    return ValidationResult(
                        is_valid=False,
                        key_id=active_rec.key_id,
                        version=active_rec.version,
                        is_previous=False,
                        error="SECRET_REVOKED"
                    )
                if active_rec.status == "ACTIVE":
                    return ValidationResult(
                        is_valid=True,
                        key_id=active_rec.key_id,
                        version=active_rec.version,
                        is_previous=False
                    )

            # Check previous secrets within grace period
            for sec_rec in self._secrets.values():
                if sec_rec.key_id == self._active_key_id:
                    continue

                if hmac.compare_digest(candidate_secret, sec_rec.secret_value):
                    # Check emergency revocation
                    if sec_rec.status == "REVOKED" or sec_rec.key_id in self._revoked_key_ids:
                        return ValidationResult(
                            is_valid=False,
                            key_id=sec_rec.key_id,
                            version=sec_rec.version,
                            is_previous=True,
                            error="SECRET_REVOKED"
                        )

                    # Check grace-period expiration
                    if sec_rec.expires_at:
                        try:
                            exp_dt = datetime.datetime.fromisoformat(sec_rec.expires_at)
                            if now_utc >= exp_dt:
                                return ValidationResult(
                                    is_valid=False,
                                    key_id=sec_rec.key_id,
                                    version=sec_rec.version,
                                    is_previous=True,
                                    error="GRACE_PERIOD_EXPIRED"
                                )
                        except Exception:
                            return ValidationResult(
                                is_valid=False,
                                key_id=sec_rec.key_id,
                                error="GRACE_PERIOD_EXPIRED"
                            )

                    # Valid previous credential within grace period
                    return ValidationResult(
                        is_valid=True,
                        key_id=sec_rec.key_id,
                        version=sec_rec.version,
                        is_previous=True
                    )

            return ValidationResult(is_valid=False, error="INVALID_SECRET")

    def rotate_secret(self, new_secret: str | None = None, grace_period_seconds: int = 3600) -> SecretRecord:
        """
        Atomically rotates secret across all processes.
        Old active secret becomes PREVIOUS with expires_at = now + grace_period.
        New secret becomes ACTIVE.
        """
        with CrossProcessLock(self.lock_path):
            with self._lock:
                self._load_from_disk()
                now_dt = datetime.datetime.now(datetime.UTC)
                now_iso = now_dt.isoformat()
                grace_exp_iso = (now_dt + datetime.timedelta(seconds=grace_period_seconds)).isoformat()

                old_active = self._secrets.get(self._active_key_id)
                if old_active and old_active.status == "ACTIVE":
                    old_active.status = "PREVIOUS"
                    old_active.expires_at = grace_exp_iso

                self._version_counter += 1
                new_ver = self._version_counter
                new_key_id = f"gw-sec-v{new_ver}-{secrets.token_hex(4)}"
                new_secret_val = new_secret or secrets.token_hex(32)

                new_rec = SecretRecord(
                    key_id=new_key_id,
                    version=new_ver,
                    secret_value=new_secret_val,
                    status="ACTIVE",
                    created_at=now_iso
                )
                self._secrets[new_key_id] = new_rec
                self._active_key_id = new_key_id

                self._save_to_disk()
                return new_rec

    def revoke_secret(self, key_id: str, reason: str = "EMERGENCY_REVOCATION") -> bool:
        """Immediately marks a secret version as REVOKED across all processes."""
        with CrossProcessLock(self.lock_path):
            with self._lock:
                self._load_from_disk()
                now_iso = datetime.datetime.now(datetime.UTC).isoformat()
                if key_id not in self._secrets and key_id not in self._revoked_key_ids:
                    return False

                self._revoked_key_ids.add(key_id)
                if key_id in self._secrets:
                    rec = self._secrets[key_id]
                    rec.status = "REVOKED"
                    rec.revoked_at = now_iso
                    rec.revocation_reason = reason

                self._save_to_disk()
                return True

    def get_metadata(self) -> dict[str, Any]:
        """Returns safe, redacted metadata for monitoring and management APIs."""
        with self._lock:
            self._refresh_if_stale()
            return {
                "active_key_id": self._active_key_id,
                "current_version": self._version_counter,
                "total_versions": len(self._secrets),
                "secrets": [s.to_metadata() for s in sorted(self._secrets.values(), key=lambda x: x.version)],
                "revoked_key_ids": sorted(list(self._revoked_key_ids))
            }


class EnvironmentSecretProvider(SecretProvider):
    """
    In-memory / Environment secret provider for localized development and testing.
    Supports in-memory zero-downtime rotation and emergency revocation.
    """

    def __init__(self, initial_secret: str | None = None):
        self._lock = threading.Lock()
        sec_val = initial_secret or os.environ.get("GATEWAY_SECRET") or secrets.token_hex(32)
        now_iso = datetime.datetime.now(datetime.UTC).isoformat()
        key_id = "gw-env-v1"
        self._active_key_id = key_id
        self._version_counter = 1
        self._secrets: dict[str, SecretRecord] = {
            key_id: SecretRecord(
                key_id=key_id,
                version=1,
                secret_value=sec_val,
                status="ACTIVE",
                created_at=now_iso
            )
        }
        self._revoked_key_ids: set[str] = set()

    def get_active_secret(self) -> SecretRecord:
        with self._lock:
            rec = self._secrets.get(self._active_key_id)
            if not rec or rec.status != "ACTIVE":
                raise RuntimeError("No active secret in EnvironmentSecretProvider.")
            return rec

    def validate_secret(self, candidate_secret: str) -> ValidationResult:
        if not candidate_secret or not isinstance(candidate_secret, str):
            return ValidationResult(is_valid=False, error="INVALID_SECRET")

        with self._lock:
            now_utc = datetime.datetime.now(datetime.UTC)
            active_rec = self._secrets.get(self._active_key_id)
            if active_rec and hmac.compare_digest(candidate_secret, active_rec.secret_value):
                if active_rec.status == "REVOKED" or active_rec.key_id in self._revoked_key_ids:
                    return ValidationResult(
                        is_valid=False,
                        key_id=active_rec.key_id,
                        version=active_rec.version,
                        is_previous=False,
                        error="SECRET_REVOKED"
                    )
                if active_rec.status == "ACTIVE":
                    return ValidationResult(
                        is_valid=True,
                        key_id=active_rec.key_id,
                        version=active_rec.version,
                        is_previous=False
                    )

            for sec_rec in self._secrets.values():
                if sec_rec.key_id == self._active_key_id:
                    continue
                if hmac.compare_digest(candidate_secret, sec_rec.secret_value):
                    if sec_rec.status == "REVOKED" or sec_rec.key_id in self._revoked_key_ids:
                        return ValidationResult(
                            is_valid=False,
                            key_id=sec_rec.key_id,
                            version=sec_rec.version,
                            is_previous=True,
                            error="SECRET_REVOKED"
                        )
                    if sec_rec.expires_at:
                        try:
                            exp_dt = datetime.datetime.fromisoformat(sec_rec.expires_at)
                            if now_utc >= exp_dt:
                                return ValidationResult(
                                    is_valid=False,
                                    key_id=sec_rec.key_id,
                                    version=sec_rec.version,
                                    is_previous=True,
                                    error="GRACE_PERIOD_EXPIRED"
                                )
                        except Exception:
                            return ValidationResult(
                                is_valid=False,
                                key_id=sec_rec.key_id,
                                error="GRACE_PERIOD_EXPIRED"
                            )
                    return ValidationResult(
                        is_valid=True,
                        key_id=sec_rec.key_id,
                        version=sec_rec.version,
                        is_previous=True
                    )

            return ValidationResult(is_valid=False, error="INVALID_SECRET")

    def rotate_secret(self, new_secret: str | None = None, grace_period_seconds: int = 3600) -> SecretRecord:
        with self._lock:
            now_dt = datetime.datetime.now(datetime.UTC)
            now_iso = now_dt.isoformat()
            grace_exp_iso = (now_dt + datetime.timedelta(seconds=grace_period_seconds)).isoformat()

            old_active = self._secrets.get(self._active_key_id)
            if old_active and old_active.status == "ACTIVE":
                old_active.status = "PREVIOUS"
                old_active.expires_at = grace_exp_iso

            self._version_counter += 1
            new_ver = self._version_counter
            new_key_id = f"gw-env-v{new_ver}"
            new_val = new_secret or secrets.token_hex(32)

            new_rec = SecretRecord(
                key_id=new_key_id,
                version=new_ver,
                secret_value=new_val,
                status="ACTIVE",
                created_at=now_iso
            )
            self._secrets[new_key_id] = new_rec
            self._active_key_id = new_key_id
            return new_rec

    def revoke_secret(self, key_id: str, reason: str = "EMERGENCY_REVOCATION") -> bool:
        with self._lock:
            now_iso = datetime.datetime.now(datetime.UTC).isoformat()
            self._revoked_key_ids.add(key_id)
            if key_id in self._secrets:
                rec = self._secrets[key_id]
                rec.status = "REVOKED"
                rec.revoked_at = now_iso
                rec.revocation_reason = reason
            return True

    def get_metadata(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active_key_id": self._active_key_id,
                "current_version": self._version_counter,
                "total_versions": len(self._secrets),
                "secrets": [s.to_metadata() for s in sorted(self._secrets.values(), key=lambda x: x.version)],
                "revoked_key_ids": sorted(list(self._revoked_key_ids))
            }


class VaultKmsSecretProvider(SecretProvider):
    """
    Enterprise External Vault/KMS Provider adapter.
    Enables production deployments to delegate secret lifecycle directly to HashiCorp Vault,
    AWS Secrets Manager, or Kubernetes Secret Manager with centralized auditing.
    """

    def __init__(self, external_client: Any, secret_name: str = "agenttrust/gateway_secret"):
        self.client = external_client
        self.secret_name = secret_name
        self._cached_provider = EnvironmentSecretProvider()

    def get_active_secret(self) -> SecretRecord:
        if hasattr(self.client, "get_secret"):
            remote_val = self.client.get_secret(self.secret_name)
            if not remote_val:
                raise ProductionConfigurationError(f"Vault/KMS returned empty secret for '{self.secret_name}'")
            active = self._cached_provider.get_active_secret()
            if active.secret_value != remote_val:
                self._cached_provider.rotate_secret(new_secret=remote_val)
        return self._cached_provider.get_active_secret()

    def validate_secret(self, candidate_secret: str) -> ValidationResult:
        # Refresh from vault before validating
        try:
            self.get_active_secret()
        except Exception:
            pass
        return self._cached_provider.validate_secret(candidate_secret)

    def rotate_secret(self, new_secret: str | None = None, grace_period_seconds: int = 3600) -> SecretRecord:
        sec = new_secret or secrets.token_hex(32)
        if hasattr(self.client, "put_secret"):
            self.client.put_secret(self.secret_name, sec)
        return self._cached_provider.rotate_secret(new_secret=sec, grace_period_seconds=grace_period_seconds)

    def revoke_secret(self, key_id: str, reason: str = "EMERGENCY_REVOCATION") -> bool:
        return self._cached_provider.revoke_secret(key_id, reason)

    def get_metadata(self) -> dict[str, Any]:
        meta = self._cached_provider.get_metadata()
        meta["provider_type"] = "VAULT_KMS_EXTERNAL"
        meta["secret_name"] = self.secret_name
        return meta


def get_centralized_secret_provider(
    env_profile: str | None = None,
    storage_path: str | None = None,
    explicit_secret: str | None = None,
    encryption_passphrase: str | None = None
) -> SecretProvider:
    """
    Factory function for obtaining the centralized secret provider.
    Enforces FAIL-CLOSED behavior in production environments.
    """
    env = str(env_profile or os.environ.get("AGENTTRUST_ENV") or "development").lower()
    is_prod = env in ("production", "prod")

    env_secret = explicit_secret or os.environ.get("GATEWAY_SECRET")
    store_path = storage_path or os.environ.get("AGENTTRUST_SECRET_STORE_PATH")

    if is_prod:
        # Production Fail-Closed Rules
        if not env_secret or env_secret in ("default_secret_key_change_in_production", "secret"):
            if not store_path or not os.path.exists(store_path):
                raise ProductionConfigurationError(
                    "SECURITY VIOLATION (FAIL-CLOSED): Production environment requires an explicit, "
                    "secure GATEWAY_SECRET or pre-provisioned encrypted secret store. Refusing to initialize."
                )

        if not store_path:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            store_path = os.path.join(project_root, ".secrets", "gateway_secrets.enc")

        return PersistentEncryptedSecretProvider(
            storage_path=store_path,
            encryption_passphrase=encryption_passphrase,
            initial_secret=env_secret,
            is_production=True
        )

    else:
        # Development / Test / Sandbox Mode
        if store_path:
            return PersistentEncryptedSecretProvider(
                storage_path=store_path,
                encryption_passphrase=encryption_passphrase,
                initial_secret=env_secret,
                is_production=False
            )
        else:
            return EnvironmentSecretProvider(initial_secret=env_secret)
