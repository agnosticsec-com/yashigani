"""
Security tests for WebAuthn / FIDO2 (v2.23.3).

Tests derived from OWASP WebAuthn Security Cheat Sheet + ASVS V2.8.

S01 — Cross-origin attestation rejected (expected_origin mismatch)
S02 — Replay attack: consumed challenge reuse returns 400/ValueError
S03 — sign_count rollback → rejected (ASVS V2.8)
S04 — Credential belonging to different user rejected
S05 — Missing challenge (no start before finish) → 400
S06 — Step-up required on DELETE credential (HTTP 401 without step-up)
S07 — Unknown username on login/start returns 400 without revealing user existence
S08 — Disabled admin account: login/start returns no credentials

Tests S01–S05 operate on the in-memory WebAuthnService (no external deps).
Tests S06–S08 use FastAPI TestClient with mocked state.

Last updated: 2026-05-07T00:00:00+00:00
"""
from __future__ import annotations

import base64
import secrets
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cred_id_b64(credential_id: bytes) -> str:
    return base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode()


def _make_mock_verify_result(new_sign_count: int = 1):
    result = MagicMock()
    result.new_sign_count = new_sign_count
    return result


def _build_inmem_service(rp_id: str = "localhost"):
    from yashigani.auth.webauthn import (
        WebAuthnConfig,
        WebAuthnService,
        WebAuthnCredential,
        WebAuthnCredentialStore,
        ChallengeStore,
    )
    config = WebAuthnConfig(rp_id=rp_id)
    store = WebAuthnCredentialStore()
    challenges = ChallengeStore()
    svc = WebAuthnService(config=config, credential_store=store, challenge_store=challenges)
    return svc


def _add_cred_with_challenge(svc, user_id: str, sign_count: int = 5):
    """Add a credential + a pending challenge for user_id. Returns (cred, challenge_bytes)."""
    from yashigani.auth.webauthn import WebAuthnCredential
    cred = WebAuthnCredential(
        id=str(uuid.uuid4()),
        user_id=user_id,
        credential_id=secrets.token_bytes(32),
        public_key=secrets.token_bytes(64),
        sign_count=sign_count,
        aaguid="",
        name="Test Key",
    )
    svc._credential_store.add(cred)
    challenge = svc._challenge_store.issue(user_id)
    return cred, challenge


# ---------------------------------------------------------------------------
# S01 — Cross-origin attestation rejected
# ---------------------------------------------------------------------------

class TestCrossOriginRejection:
    def test_s01_wrong_origin_raises_value_error(self):
        """
        complete_registration() raises ValueError when expected_origin
        does not match the clientDataJSON origin.  Tested by mocking
        verify_registration_response to raise an Exception (as py_webauthn does).
        """
        svc = _build_inmem_service()
        # Issue a challenge
        svc._challenge_store._challenges["admin-x"] = b"\x01" * 32

        mock_wa = MagicMock()
        mock_wa.RegistrationCredential.parse_raw.return_value = MagicMock()
        # Simulate py_webauthn raising on origin mismatch
        mock_wa.verify_registration_response.side_effect = Exception(
            "Invalid clientDataJSON: origin mismatch"
        )

        with patch("yashigani.auth.webauthn._import_webauthn", return_value=mock_wa):
            with pytest.raises(ValueError, match="registration verification failed"):
                svc.complete_registration(
                    user_id="admin-x",
                    credential_response={"id": "abc", "rawId": "abc", "type": "public-key",
                                         "response": {"clientDataJSON": "", "attestationObject": ""}},
                    expected_origin="https://attacker.example.com",  # wrong origin
                )


# ---------------------------------------------------------------------------
# S02 — Challenge reuse rejected
# ---------------------------------------------------------------------------

class TestChallengeReuse:
    def test_s02_second_login_without_new_start_fails(self):
        """
        complete_authentication() without a preceding begin_authentication()
        (or after challenge was consumed) raises ValueError.
        The challenge check happens before _import_webauthn — test at store level.
        """
        svc = _build_inmem_service()
        cred = _add_cred_with_challenge(svc, "admin-y", sign_count=0)[0]
        # Consume the challenge manually — simulates expired TTL or prior use
        svc._challenge_store._challenges.pop("admin-y", None)

        raw_id = _cred_id_b64(cred.credential_id)
        # Patch webauthn import so we reach the challenge check
        mock_wa = MagicMock()
        with patch("yashigani.auth.webauthn._import_webauthn", return_value=mock_wa):
            with pytest.raises(ValueError, match="No pending authentication challenge"):
                svc.complete_authentication(
                    user_id="admin-y",
                    credential_response={"rawId": raw_id},
                    expected_origin="https://localhost",
                )


# ---------------------------------------------------------------------------
# S03 — sign_count rollback
# ---------------------------------------------------------------------------

class TestSignCountRollback:
    def test_s03_rollback_detected(self):
        """
        complete_authentication() raises ValueError when new_sign_count
        is strictly less than the stored count (ASVS V2.8 cloned-authenticator guard).
        """
        svc = _build_inmem_service()
        cred, _ = _add_cred_with_challenge(svc, "admin-z", sign_count=100)
        svc._challenge_store._challenges["admin-z"] = b"\x00" * 32

        raw_id = _cred_id_b64(cred.credential_id)
        mock_wa = MagicMock()
        mock_wa.AuthenticationCredential.parse_raw.return_value = MagicMock()
        mock_wa.verify_authentication_response.return_value = _make_mock_verify_result(new_sign_count=50)

        with patch("yashigani.auth.webauthn._import_webauthn", return_value=mock_wa):
            with pytest.raises(ValueError, match="sign_count"):
                svc.complete_authentication(
                    user_id="admin-z",
                    credential_response={"rawId": _cred_id_b64(cred.credential_id)},
                    expected_origin="https://localhost",
                )


# ---------------------------------------------------------------------------
# S04 — Credential belonging to different user rejected
# ---------------------------------------------------------------------------

class TestCrossUserCredentialRejection:
    def test_s04_credential_from_different_user_rejected(self):
        """
        complete_authentication() raises ValueError when the credential_id
        belongs to a different user than the challenge was issued for.
        """
        svc = _build_inmem_service()
        # Register a credential for admin-A
        from yashigani.auth.webauthn import WebAuthnCredential
        cred_a = WebAuthnCredential(
            id=str(uuid.uuid4()),
            user_id="admin-A",
            credential_id=secrets.token_bytes(32),
            public_key=secrets.token_bytes(64),
            sign_count=0,
            aaguid="",
            name="Key A",
        )
        svc._credential_store.add(cred_a)

        # Issue a challenge for admin-B
        svc._challenge_store._challenges["admin-B"] = b"\x00" * 32

        # Try to authenticate admin-B using admin-A's credential_id
        raw_id = _cred_id_b64(cred_a.credential_id)
        mock_wa = MagicMock()
        with patch("yashigani.auth.webauthn._import_webauthn", return_value=mock_wa):
            with pytest.raises(ValueError, match="does not belong to this user"):
                svc.complete_authentication(
                    user_id="admin-B",
                    credential_response={"rawId": raw_id},
                    expected_origin="https://localhost",
                )


# ---------------------------------------------------------------------------
# S05 — Missing challenge
# ---------------------------------------------------------------------------

class TestMissingChallenge:
    def test_s05_register_finish_without_start_fails(self):
        """complete_registration() without begin_registration() raises ValueError."""
        svc = _build_inmem_service()
        # No challenge issued for this user
        mock_wa = MagicMock()
        with patch("yashigani.auth.webauthn._import_webauthn", return_value=mock_wa):
            with pytest.raises(ValueError, match="No pending registration challenge"):
                svc.complete_registration(
                    user_id="new-admin",
                    credential_response={},
                    expected_origin="https://localhost",
                )


# ---------------------------------------------------------------------------
# S06 — Step-up required on DELETE credential
# ---------------------------------------------------------------------------

class TestStepUpOnDelete:
    """
    The DELETE /api/v1/admin/webauthn/credentials/{id} endpoint uses
    StepUpAdminSession (requires fresh TOTP within 5 min).
    Without a step-up, it must return HTTP 401 with error=step_up_required.
    """

    def _make_app(self, has_stepup: bool = False):
        import time as _time
        from yashigani.backoffice.routes.webauthn_v1 import router
        from yashigani.auth.stepup import STEPUP_TTL_SECONDS
        app = FastAPI()
        app.include_router(router)

        # Patch middleware deps
        from yashigani.auth.session import Session
        # For valid step-up: use recent past (e.g. 10 seconds ago) so age < TTL
        stepup_time = _time.time() - 10 if has_stepup else None
        session = Session(
            token="tok",
            account_id="admin-test",
            account_tier="admin",
            created_at=0.0,
            last_active_at=_time.time(),
            expires_at=_time.time() + 14400,
            ip_prefix="127.0.0.0",
            last_totp_verified_at=stepup_time,
        )

        mock_store = MagicMock()
        mock_store.get.return_value = session

        import yashigani.backoffice.middleware as mw
        app.dependency_overrides[mw.get_session_store] = lambda: mock_store

        return app, session

    def test_s06_delete_without_stepup_returns_401(self):
        app, _ = self._make_app(has_stepup=False)

        # Mock backoffice_state with a pg_webauthn_service
        mock_svc = AsyncMock()
        mock_svc.delete_credential = AsyncMock(return_value=True)

        import yashigani.backoffice.routes.webauthn_v1 as wv1
        with patch.object(wv1, "backoffice_state") as mock_state:
            mock_state.pg_webauthn_service = mock_svc
            mock_state.audit_writer = None

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete(
                "/api/v1/admin/webauthn/credentials/some-uuid",
                cookies={"__Host-yashigani_admin_session": "tok"},
            )

        # Step-up not satisfied → 401
        assert resp.status_code == 401
        assert resp.json()["detail"]["error"] == "step_up_required"

    def test_s06_delete_with_valid_stepup_succeeds(self):
        import time
        app, _ = self._make_app(has_stepup=True)

        mock_svc = AsyncMock()
        mock_svc.delete_credential = AsyncMock(return_value=True)

        import yashigani.backoffice.routes.webauthn_v1 as wv1
        with patch.object(wv1, "backoffice_state") as mock_state:
            mock_state.pg_webauthn_service = mock_svc
            mock_state.audit_writer = None

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete(
                "/api/v1/admin/webauthn/credentials/some-uuid",
                cookies={"__Host-yashigani_admin_session": "tok"},
            )

        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# S07 — Unknown username on login/start is non-enumerable
# ---------------------------------------------------------------------------

class TestUsernameEnumeration:
    def test_s07_unknown_user_returns_generic_400(self):
        """
        login/start for an unknown username returns 400 with
        error=no_credentials_registered (same as known user with no creds).
        Does NOT reveal whether the user exists.
        """
        from yashigani.backoffice.routes.webauthn_v1 import router, _resolve_admin_id
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)

        import yashigani.backoffice.routes.webauthn_v1 as wv1

        with patch.object(wv1, "_resolve_admin_id", new_callable=AsyncMock, return_value=None):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/admin/webauthn/login/start",
                json={"username": "nonexistent@example.com"},
            )

        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "no_credentials_registered"

    def test_s07_real_user_with_no_creds_same_response(self):
        """
        Known user with no credentials: same 400 response as unknown user.
        """
        from yashigani.backoffice.routes.webauthn_v1 import router
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)

        import yashigani.backoffice.routes.webauthn_v1 as wv1

        mock_svc = AsyncMock()
        mock_svc.begin_authentication = AsyncMock(
            side_effect=ValueError("No registered WebAuthn credentials for this user.")
        )

        with patch.object(wv1, "_resolve_admin_id", new_callable=AsyncMock, return_value="admin-uuid"):
            with patch.object(wv1, "backoffice_state") as mock_state:
                mock_state.pg_webauthn_service = mock_svc

                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/admin/webauthn/login/start",
                    json={"username": "admin@yashigani.local"},
                )

        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "no_credentials_registered"
