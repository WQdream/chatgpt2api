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
            return {"token": "sentinel-value", "so_token": "so-value"}

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

        self.assertEqual(result.token, "sentinel-value")
        self.assertEqual(result.so_token, "so-value")
        self.assertEqual(result.sdk_version, "20260219f9f6")
        self.assertEqual(runtime_calls[0]["observer_wait_ms"], 5000)
        self.assertEqual(runtime_calls[0]["device_id"], "device-id")
        self.assertEqual(runtime_calls[0]["proxy"], "http://127.0.0.1:7890")

    def test_generate_rejects_missing_so_token(self):
        descriptor = sentinel.SentinelSDKDescriptor(
            version="20260219f9f6",
            script_url="https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        )
        with patch.object(sentinel, "discover_official_sdk", return_value=descriptor), patch.object(
            sentinel,
            "run_official_sdk",
            return_value={"token": "sentinel-value", "so_token": ""},
        ):
            with self.assertRaisesRegex(RuntimeError, "so_token_missing"):
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


if __name__ == "__main__":
    unittest.main()
