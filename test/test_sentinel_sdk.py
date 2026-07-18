import base64
import json
import os
import unittest
import uuid
from unittest.mock import patch

from utils import sentinel


class FakeResponse:
    status_code = 200
    text = "<html><script src='https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js'></script></html>"


class FakeSession:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse()


class OfficialSentinelSDKTests(unittest.TestCase):
    @staticmethod
    def _combined_token(
        flow="oauth_create_account",
        *,
        proof="proof-value",
        turnstile="turnstile-value",
        challenge="challenge-value",
    ):
        return json.dumps(
            {
                "p": proof,
                "t": turnstile,
                "c": challenge,
                "id": "device-id",
                "flow": flow,
            },
            separators=(",", ":"),
        )

    @staticmethod
    def _requirements(*, proof=True, turnstile=True, so=True):
        return {
            "proofofwork": {"required": proof},
            "turnstile": {"required": turnstile},
            "so": {"required": so},
            "token": "challenge-value",
        }

    def test_discovers_current_sdk_from_official_frame(self):
        session = FakeSession()

        descriptor = sentinel.discover_official_sdk(session, user_agent="Browser UA")

        self.assertEqual(descriptor.version, "20260219f9f6")
        self.assertEqual(
            descriptor.script_url,
            "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        )
        self.assertEqual(session.calls[0][0], sentinel.SENTINEL_FRAME_URL)
        self.assertEqual(session.calls[0][1]["headers"]["User-Agent"], "Browser UA")
        self.assertTrue(session.calls[0][1]["verify"])

    def test_rejects_sdk_script_outside_official_https_origin(self):
        class UntrustedResponse(FakeResponse):
            text = "<script src='https://example.invalid/sentinel/build/sdk.js'></script>"

        class UntrustedSession(FakeSession):
            def get(self, url, **kwargs):
                self.calls.append((url, kwargs))
                return UntrustedResponse()

        with self.assertRaisesRegex(RuntimeError, "untrusted"):
            sentinel.discover_official_sdk(UntrustedSession())

    def test_browser_expression_uses_official_sdk_and_5000ms_observer_wait(self):
        expression = sentinel.build_sdk_evaluation_expression(
            "oauth_create_account",
            observer_wait_ms=5000,
        )

        self.assertIn("SentinelSDK.init", expression)
        self.assertIn("SentinelSDK.token", expression)
        self.assertIn("SentinelSDK.sessionObserverToken", expression)
        self.assertIn("setTimeout(resolve, 5000)", expression)

    def test_generate_returns_both_tokens_and_sdk_version(self):
        descriptor = sentinel.SentinelSDKDescriptor(
            version="20260219f9f6",
            script_url="https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        )
        runtime_calls = []

        def fake_runtime(**kwargs):
            runtime_calls.append(kwargs)
            return {
                "token": self._combined_token(),
                "so_token": "so-value",
                "oai_sc": "oai-sc-value",
                "requirements": self._requirements(),
            }

        with patch.object(sentinel, "discover_official_sdk", return_value=descriptor), patch.object(
            sentinel,
            "run_official_sdk",
            side_effect=fake_runtime,
        ):
            result = sentinel.generate_official_sentinel_tokens(
                FakeSession(),
                "device-id",
                "oauth_create_account",
                user_agent="Browser UA",
                proxy="http://127.0.0.1:7890",
            )

        self.assertEqual(result.token, self._combined_token())
        self.assertEqual(result.so_token, "so-value")
        self.assertEqual(result.oai_sc, "oai-sc-value")
        self.assertEqual(result.sdk_version, "20260219f9f6")
        self.assertEqual(result.proof_token, "proof-value")
        self.assertEqual(result.turnstile_token, "turnstile-value")
        self.assertEqual(result.challenge_token, "challenge-value")
        self.assertTrue(result.requirements["so"])
        self.assertEqual(runtime_calls[0]["observer_wait_ms"], 5000)
        self.assertEqual(runtime_calls[0]["device_id"], "device-id")
        self.assertEqual(runtime_calls[0]["proxy"], "http://127.0.0.1:7890")

    def test_oauth_flow_rejects_missing_oai_sc_cookie(self):
        descriptor = sentinel.SentinelSDKDescriptor(
            version="20260219f9f6",
            script_url="https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        )
        with patch.object(sentinel, "discover_official_sdk", return_value=descriptor), patch.object(
            sentinel,
            "run_official_sdk",
            return_value={
                "token": self._combined_token(),
                "so_token": "so-value",
                "oai_sc": "",
                "requirements": self._requirements(),
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "oai_sc_missing"):
                sentinel.build_sentinel_bundle(
                    FakeSession(),
                    "device-id",
                    "oauth_create_account",
                )

    def test_generate_rejects_missing_so_token(self):
        descriptor = sentinel.SentinelSDKDescriptor(
            version="20260219f9f6",
            script_url="https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        )
        with patch.object(sentinel, "discover_official_sdk", return_value=descriptor), patch.object(
            sentinel,
            "run_official_sdk",
            return_value={
                "token": self._combined_token(),
                "so_token": "",
                "requirements": self._requirements(so=True),
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "so_token_missing"):
                sentinel.generate_official_sentinel_tokens(
                    FakeSession(),
                    "device-id",
                    "oauth_create_account",
                )

    def test_username_flow_requires_proof_turnstile_and_challenge_but_not_so(self):
        descriptor = sentinel.SentinelSDKDescriptor(
            version="20260219f9f6",
            script_url="https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        )
        username_requirements = self._requirements(so=False)
        username_requirements.pop("so")
        with patch.object(sentinel, "discover_official_sdk", return_value=descriptor), patch.object(
            sentinel,
            "run_official_sdk",
            return_value={
                "token": self._combined_token(flow="username_password_create"),
                "so_token": "",
                "requirements": username_requirements,
            },
        ):
            result = sentinel.generate_official_sentinel_tokens(
                FakeSession(),
                "device-id",
                "username_password_create",
            )

        self.assertEqual(result.so_token, "")
        self.assertTrue(result.requirements["proof"])
        self.assertTrue(result.requirements["turnstile"])
        self.assertFalse(result.requirements["so"])

    def test_required_turnstile_rejects_base64_runtime_error(self):
        descriptor = sentinel.SentinelSDKDescriptor(
            version="20260219f9f6",
            script_url="https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        )
        runtime_error = base64.b64encode(
            b"TypeError: Cannot read properties of undefined (reading 'bind')"
        ).decode("ascii")
        with patch.object(sentinel, "discover_official_sdk", return_value=descriptor), patch.object(
            sentinel,
            "run_official_sdk",
            return_value={
                "token": self._combined_token(turnstile=runtime_error),
                "so_token": "so-value",
                "requirements": self._requirements(),
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "turnstile_token_invalid"):
                sentinel.generate_official_sentinel_tokens(
                    FakeSession(),
                    "device-id",
                    "oauth_create_account",
                )

    def test_required_turnstile_rejects_missing_token(self):
        descriptor = sentinel.SentinelSDKDescriptor(
            version="20260219f9f6",
            script_url="https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        )
        with patch.object(sentinel, "discover_official_sdk", return_value=descriptor), patch.object(
            sentinel,
            "run_official_sdk",
            return_value={
                "token": self._combined_token(turnstile=""),
                "so_token": "so-value",
                "requirements": self._requirements(),
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "turnstile_token_missing"):
                sentinel.generate_official_sentinel_tokens(
                    FakeSession(),
                    "device-id",
                    "oauth_create_account",
                )

    def test_generate_rejects_missing_requirements(self):
        descriptor = sentinel.SentinelSDKDescriptor(
            version="20260219f9f6",
            script_url="https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        )
        with patch.object(sentinel, "discover_official_sdk", return_value=descriptor), patch.object(
            sentinel,
            "run_official_sdk",
            return_value={
                "token": self._combined_token(),
                "so_token": "so-value",
                "requirements": {"error": "sentinel request failed"},
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "requirements_missing"):
                sentinel.generate_official_sentinel_tokens(
                    FakeSession(),
                    "device-id",
                    "oauth_create_account",
                )

    def test_generate_rejects_sdk_error_field_in_combined_token(self):
        descriptor = sentinel.SentinelSDKDescriptor(
            version="20260219f9f6",
            script_url="https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        )
        combined = json.loads(self._combined_token())
        combined["e"] = "turnstile runtime failed"
        with patch.object(sentinel, "discover_official_sdk", return_value=descriptor), patch.object(
            sentinel,
            "run_official_sdk",
            return_value={
                "token": json.dumps(combined, separators=(",", ":")),
                "so_token": "so-value",
                "requirements": self._requirements(),
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "combined_token_invalid"):
                sentinel.generate_official_sentinel_tokens(
                    FakeSession(),
                    "device-id",
                    "oauth_create_account",
                )

    def test_generate_rejects_missing_challenge_token(self):
        descriptor = sentinel.SentinelSDKDescriptor(
            version="20260219f9f6",
            script_url="https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        )
        with patch.object(sentinel, "discover_official_sdk", return_value=descriptor), patch.object(
            sentinel,
            "run_official_sdk",
            return_value={
                "token": self._combined_token(challenge=""),
                "so_token": "so-value",
                "requirements": self._requirements(),
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "challenge_token_missing"):
                sentinel.generate_official_sentinel_tokens(
                    FakeSession(),
                    "device-id",
                    "oauth_create_account",
                )

    @unittest.skipUnless(os.getenv("RUN_SENTINEL_INTEGRATION") == "1", "set RUN_SENTINEL_INTEGRATION=1")
    def test_live_official_sdk_generates_both_tokens_in_chromium(self):
        from curl_cffi import requests

        session = requests.Session(impersonate="chrome")
        try:
            result = sentinel.generate_official_sentinel_tokens(
                session,
                str(uuid.uuid4()),
                "oauth_create_account",
            )
        finally:
            session.close()

        self.assertTrue(result.sdk_version)
        self.assertGreater(len(result.token), 100)
        self.assertGreater(len(result.so_token), 100)
        self.assertGreater(len(result.proof_token), 100)
        self.assertGreater(len(result.turnstile_token), 100)
        self.assertGreater(len(result.challenge_token), 100)
        self.assertGreater(len(result.oai_sc), 100)
        self.assertTrue(result.requirements["proof"])
        self.assertTrue(result.requirements["turnstile"])
        self.assertTrue(result.requirements["so"])


if __name__ == "__main__":
    unittest.main()
