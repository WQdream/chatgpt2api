import os
import unittest

os.environ.setdefault("CHATGPT2API_AUTH_KEY", "test-auth")

from services.cpa_service import _payload_access_token
from services.sub2api_service import _extract_account_payload


class AccountImportPayloadTests(unittest.TestCase):
    def test_cpa_payload_accepts_access_token_alias(self) -> None:
        self.assertEqual(_payload_access_token({"accessToken": "token-test"}), "token-test")

    def test_sub2api_payload_preserves_refresh_credentials(self) -> None:
        payload = _extract_account_payload(
            {"id": "remote-id", "name": "remote@example.com"},
            {
                "access_token": "access-test",
                "refresh_token": "refresh-test",
                "id_token": "id-test",
                "client_id": "client-test",
                "email": "account@example.com",
                "chatgpt_account_id": "acct-test",
                "plan_type": "plus",
            },
        )

        self.assertEqual(payload["access_token"], "access-test")
        self.assertEqual(payload["refresh_token"], "refresh-test")
        self.assertEqual(payload["id_token"], "id-test")
        self.assertEqual(payload["client_id"], "client-test")
        self.assertEqual(payload["email"], "account@example.com")
        self.assertEqual(payload["account_id"], "acct-test")
        self.assertEqual(payload["plan_type"], "plus")

    def test_sub2api_payload_reads_nested_token_credentials(self) -> None:
        payload = _extract_account_payload(
            {"id": "remote-id"},
            {
                "token": {
                    "access_token": "access-test",
                    "refresh_token": "refresh-test",
                    "id_token": "id-test",
                    "client_id": "client-test",
                },
            },
        )

        self.assertEqual(payload["access_token"], "access-test")
        self.assertEqual(payload["refresh_token"], "refresh-test")
        self.assertEqual(payload["id_token"], "id-test")
        self.assertEqual(payload["client_id"], "client-test")


if __name__ == "__main__":
    unittest.main()
