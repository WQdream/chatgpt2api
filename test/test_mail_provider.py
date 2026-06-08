import unittest

from services.register import mail_provider


class DummySession:
    def close(self) -> None:
        pass


class FreemailProviderTests(unittest.TestCase):
    def test_freemail_provider_uses_shared_session_factory(self) -> None:
        calls = []
        old_create_session = mail_provider._create_session

        def fake_create_session(conf: dict) -> DummySession:
            calls.append(conf)
            return DummySession()

        try:
            mail_provider._create_session = fake_create_session
            conf = {
                "request_timeout": 30,
                "wait_timeout": 30,
                "wait_interval": 2,
                "user_agent": "Mozilla/5.0",
                "proxy": "",
            }
            provider = mail_provider.FreemailProvider(
                {
                    "provider_ref": "freemail#1",
                    "api_base": "https://example.test",
                    "jwt_token": "test-token",
                    "domain": ["example.com"],
                    "domain_index_map": {"example.com": 0},
                },
                conf,
            )

            self.assertIsInstance(provider.session, DummySession)
            self.assertEqual(calls, [conf])
        finally:
            mail_provider._create_session = old_create_session


if __name__ == "__main__":
    unittest.main()
