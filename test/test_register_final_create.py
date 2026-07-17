import unittest
from unittest.mock import patch

from services.register import openai_register
from utils.sentinel import SentinelSDKTokens


class FakeCookies:
    def set(self, *args, **kwargs):
        return None


class FakeSession:
    def __init__(self):
        self.cookies = FakeCookies()
        self.headers = {}

    def close(self):
        return None


class FakeResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data or {}
        self.text = "{}"
        self.url = "https://auth.openai.com/test"
        self.headers = {"content-type": "application/json"}

    def json(self):
        return self._data


class RegisterFinalCreateTests(unittest.TestCase):
    def _registrar(self):
        with patch.object(openai_register, "create_session", return_value=FakeSession()):
            return openai_register.PlatformRegistrar(proxy="http://127.0.0.1:7890")

    def test_email_submission_calls_authorize_continue_with_browser_payload(self):
        registrar = self._registrar()
        calls = []

        def fake_request(session, method, url, **kwargs):
            calls.append({"method": method, "url": url, **kwargs})
            return FakeResponse(), ""

        with patch.object(openai_register, "build_sentinel_token", return_value="email-sentinel"), patch.object(
            openai_register,
            "request_with_local_retry",
            side_effect=fake_request,
        ):
            registrar._continue_with_email("person@example.com", 1)

        self.assertEqual(calls[0]["url"], "https://auth.openai.com/api/accounts/authorize/continue")
        self.assertEqual(
            calls[0]["json"],
            {"username": {"kind": "email", "value": "person@example.com"}},
        )
        headers = {key.lower(): value for key, value in calls[0]["headers"].items()}
        self.assertEqual(headers["openai-sentinel-token"], "email-sentinel")

    def test_create_account_sends_sdk_generated_sentinel_and_so_headers(self):
        registrar = self._registrar()
        calls = []
        logs = []
        tokens = SentinelSDKTokens(
            token="sdk-sentinel-secret",
            so_token="sdk-so-secret",
            sdk_version="20260219f9f6",
        )

        def fake_request(session, method, url, **kwargs):
            calls.append({"method": method, "url": url, **kwargs})
            return FakeResponse(data={"continue_url": "https://platform.openai.com/auth/callback?code=oauth-code"}), ""

        with patch.object(openai_register, "generate_official_sentinel_tokens", return_value=tokens), patch.object(
            openai_register,
            "request_with_local_retry",
            side_effect=fake_request,
        ), patch.object(openai_register, "step", side_effect=lambda _index, text, _color="": logs.append(text)):
            registrar._create_account("Example User", "2000-01-01", 1)

        headers = calls[0]["headers"]
        self.assertEqual(headers["OpenAI-Sentinel-Token"], "sdk-sentinel-secret")
        self.assertEqual(headers["OpenAI-Sentinel-SO-Token"], "sdk-so-secret")
        joined_logs = "\n".join(logs)
        self.assertIn("sdk_version=20260219f9f6", joined_logs)
        self.assertIn("token_length=19", joined_logs)
        self.assertIn("so_token_generated=True", joined_logs)
        self.assertNotIn("so_token_length", joined_logs)
        self.assertNotIn("sdk-sentinel-secret", joined_logs)
        self.assertNotIn("sdk-so-secret", joined_logs)

    def test_password_registration_uses_official_sdk_turnstile_token(self):
        registrar = self._registrar()
        calls = []
        logs = []
        tokens = SentinelSDKTokens(
            token="sdk-username-combined-secret",
            so_token="",
            sdk_version="20260219f9f6",
            proof_token="proof-secret",
            turnstile_token="turnstile-secret",
            challenge_token="challenge-secret",
            requirements={"proof": True, "turnstile": True, "so": False},
        )

        def fake_request(session, method, url, **kwargs):
            calls.append({"method": method, "url": url, **kwargs})
            return FakeResponse(), ""

        with patch.object(openai_register, "generate_official_sentinel_tokens", return_value=tokens) as generate, patch.object(
            openai_register,
            "request_with_local_retry",
            side_effect=fake_request,
        ), patch.object(openai_register, "step", side_effect=lambda _index, text, _color="": logs.append(text)):
            registrar._register_user("person@example.com", "Password!123", 1)

        generate.assert_called_once()
        self.assertEqual(generate.call_args.args[2], "username_password_create")
        self.assertEqual(calls[0]["headers"]["OpenAI-Sentinel-Token"], "sdk-username-combined-secret")
        joined_logs = "\n".join(logs)
        self.assertIn("flow=username_password_create", joined_logs)
        self.assertIn("p_length=12", joined_logs)
        self.assertIn("t_length=16", joined_logs)
        self.assertIn("c_length=16", joined_logs)
        self.assertNotIn("proof-secret", joined_logs)
        self.assertNotIn("turnstile-secret", joined_logs)
        self.assertNotIn("challenge-secret", joined_logs)

    def test_password_registration_refreshes_official_sdk_token_after_cloudflare(self):
        registrar = self._registrar()
        calls = []
        first = SentinelSDKTokens(
            token="first-combined-token",
            so_token="",
            sdk_version="20260219f9f6",
            proof_token="proof-1",
            turnstile_token="turnstile-1",
            challenge_token="challenge-1",
            requirements={"proof": True, "turnstile": True, "so": False},
        )
        second = SentinelSDKTokens(
            token="second-combined-token",
            so_token="",
            sdk_version="20260219f9f6",
            proof_token="proof-2",
            turnstile_token="turnstile-2",
            challenge_token="challenge-2",
            requirements={"proof": True, "turnstile": True, "so": False},
        )

        def fake_request(session, method, url, **kwargs):
            calls.append({"method": method, "url": url, **kwargs})
            return FakeResponse(), ""

        with patch.object(
            openai_register,
            "generate_official_sentinel_tokens",
            side_effect=[first, second],
        ) as generate, patch.object(
            openai_register,
            "request_with_local_retry",
            side_effect=fake_request,
        ), patch.object(
            openai_register,
            "_is_cloudflare_challenge",
            side_effect=[True, False],
        ), patch.object(
            registrar,
            "_refresh_cloudflare_clearance",
            return_value=object(),
        ), patch.object(openai_register, "step"):
            registrar._register_user("person@example.com", "Password!123", 1)

        self.assertEqual(generate.call_count, 2)
        self.assertEqual(calls[0]["headers"]["OpenAI-Sentinel-Token"], "first-combined-token")
        self.assertEqual(calls[1]["headers"]["OpenAI-Sentinel-Token"], "second-combined-token")

    def test_registration_disallowed_log_points_to_sdk_diagnostics_without_token_values(self):
        registrar = self._registrar()
        logs = []
        tokens = SentinelSDKTokens(
            token="sdk-sentinel-secret",
            so_token="sdk-so-secret",
            sdk_version="20260219f9f6",
        )
        response = FakeResponse(
            status_code=400,
            data={
                "code": "registration_disallowed",
                "message": "Sorry, we cannot create your account with the given information.",
            },
        )
        with patch.object(openai_register, "generate_official_sentinel_tokens", return_value=tokens), patch.object(
            openai_register,
            "request_with_local_retry",
            return_value=(response, ""),
        ), patch.object(openai_register, "step", side_effect=lambda _index, text, _color="": logs.append(text)):
            with self.assertRaisesRegex(RuntimeError, "registration_disallowed"):
                registrar._create_account("Example User", "2000-01-01", 1)

        joined_logs = "\n".join(logs)
        self.assertIn("registration_disallowed", joined_logs)
        self.assertIn("sdk_version=20260219f9f6", joined_logs)
        self.assertIn("so_token_generated=True", joined_logs)
        self.assertNotIn("sdk-sentinel-secret", joined_logs)
        self.assertNotIn("sdk-so-secret", joined_logs)

    def test_password_registration_failure_does_not_guess_email_domain_cause(self):
        registrar = self._registrar()
        logs = []
        tokens = SentinelSDKTokens(
            token="sdk-username-combined-secret",
            so_token="",
            sdk_version="20260219f9f6",
        )
        response = FakeResponse(
            status_code=400,
            data={"message": "Failed to create account. Please try again."},
        )
        with patch.object(openai_register, "generate_official_sentinel_tokens", return_value=tokens), patch.object(
            openai_register,
            "request_with_local_retry",
            return_value=(response, ""),
        ), patch.object(openai_register, "step", side_effect=lambda _index, text, _color="": logs.append(text)):
            with self.assertRaisesRegex(RuntimeError, "user_register_http_400"):
                registrar._register_user("person@example.com", "Password!123", 1)

        self.assertNotIn("邮箱域名", "\n".join(logs))

    def test_create_account_failure_does_not_guess_email_domain_cause(self):
        registrar = self._registrar()
        logs = []
        tokens = SentinelSDKTokens(
            token="sdk-sentinel-secret",
            so_token="sdk-so-secret",
            sdk_version="20260219f9f6",
        )
        response = FakeResponse(
            status_code=400,
            data={"message": "Failed to create account. Please try again."},
        )
        with patch.object(openai_register, "generate_official_sentinel_tokens", return_value=tokens), patch.object(
            openai_register,
            "request_with_local_retry",
            return_value=(response, ""),
        ), patch.object(openai_register, "step", side_effect=lambda _index, text, _color="": logs.append(text)):
            with self.assertRaisesRegex(RuntimeError, "create_account_http_400"):
                registrar._create_account("Example User", "2000-01-01", 1)

        self.assertNotIn("邮箱域名", "\n".join(logs))

    def test_register_sequence_advances_email_before_password(self):
        registrar = self._registrar()
        order = []
        mailbox = {"address": "person@example.com", "provider": "fixture", "provider_ref": "fixture#1"}
        tokens = {"access_token": "access", "refresh_token": "refresh", "id_token": "id"}

        with patch.object(openai_register, "create_mailbox", return_value=mailbox), patch.object(
            registrar,
            "_platform_authorize",
            side_effect=lambda *_: order.append("authorize"),
        ), patch.object(
            registrar,
            "_continue_with_email",
            side_effect=lambda *_: order.append("continue_email"),
        ), patch.object(
            registrar,
            "_register_user",
            side_effect=lambda *_: order.append("register_password"),
        ), patch.object(registrar, "_send_otp"), patch.object(
            openai_register,
            "wait_for_code",
            return_value="123456",
        ), patch.object(registrar, "_validate_otp"), patch.object(registrar, "_create_account"), patch.object(
            registrar,
            "_exchange_registered_tokens",
            return_value=tokens,
        ), patch.object(openai_register.mail_provider, "mark_mailbox_result"):
            registrar.register(1)

        self.assertEqual(order, ["authorize", "continue_email", "register_password"])


if __name__ == "__main__":
    unittest.main()
