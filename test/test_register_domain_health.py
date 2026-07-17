import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from services.register.domain_health import DomainHealthTracker
from services.register import mail_provider


class RegisterDomainHealthTests(unittest.TestCase):
    def test_low_success_domain_is_disabled_after_minimum_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            tracker = DomainHealthTracker(Path(directory) / "domain-health.json")
            policy = {"enabled": True, "min_samples": 3, "min_success_rate": 50}
            mailbox = {
                "provider": "fixture",
                "provider_ref": "fixture#1",
                "address": "user@bad.example",
            }

            tracker.record(mailbox, success=False, error="registration_disallowed", policy=policy)
            tracker.record(mailbox, success=False, error="registration_disallowed", policy=policy)
            self.assertFalse(tracker.is_disabled("fixture#1", "bad.example"))
            tracker.record(mailbox, success=False, error="registration_disallowed", policy=policy)

            self.assertTrue(tracker.is_disabled("fixture#1", "bad.example"))
            row = tracker.snapshot()[0]
            self.assertEqual(row["attempts"], 3)
            self.assertEqual(row["success_rate"], 0.0)
            self.assertTrue(row["disabled"])

    def test_disabled_domains_are_removed_from_provider_choices(self):
        with tempfile.TemporaryDirectory() as directory:
            tracker = DomainHealthTracker(Path(directory) / "domain-health.json")
            policy = {"enabled": True, "min_samples": 1, "min_success_rate": 50}
            tracker.record(
                {"provider": "fixture", "provider_ref": "fixture#1", "address": "user@bad.example"},
                success=False,
                error="registration_disallowed",
                policy=policy,
            )

            remaining = tracker.filter_domains("fixture#1", ["good.example", "bad.example"])

            self.assertEqual(remaining, ["good.example"])

    def test_base_domain_is_used_for_random_subdomain_mailboxes(self):
        with tempfile.TemporaryDirectory() as directory:
            tracker = DomainHealthTracker(Path(directory) / "domain-health.json")
            tracker.record(
                {
                    "provider": "inbucket",
                    "provider_ref": "inbucket#1",
                    "address": "user@random.base.example",
                    "base_domain": "base.example",
                },
                success=True,
                policy={"enabled": True, "min_samples": 3, "min_success_rate": 50},
            )

            self.assertEqual(tracker.snapshot()[0]["domain"], "base.example")

    def test_enabled_provider_domains_are_filtered_by_health_tracker(self):
        config = {
            "providers": [
                {
                    "enable": True,
                    "type": "freemail",
                    "domain": ["good.example", "bad.example"],
                }
            ]
        }
        with patch.object(
            mail_provider.domain_health_tracker,
            "filter_domains",
            return_value=["good.example"],
        ):
            entries = mail_provider._enabled_entries(config)

        self.assertEqual(entries[0]["domain"], ["good.example"])

    def test_disabled_policy_keeps_configured_domains_available(self):
        config = {
            "domain_health": {"enabled": False, "min_samples": 1, "min_success_rate": 100},
            "providers": [
                {
                    "enable": True,
                    "type": "freemail",
                    "domain": ["good.example", "bad.example"],
                }
            ],
        }
        with patch.object(
            mail_provider.domain_health_tracker,
            "filter_domains",
            return_value=["good.example"],
        ) as filter_domains:
            entries = mail_provider._enabled_entries(config)

        self.assertEqual(entries[0]["domain"], ["good.example", "bad.example"])
        filter_domains.assert_not_called()

    def test_mark_mailbox_result_records_every_provider(self):
        mailbox = {
            "provider": "freemail",
            "provider_ref": "freemail#1",
            "address": "user@example.com",
        }
        mail_config = {
            "domain_health": {"enabled": True, "min_samples": 3, "min_success_rate": 50}
        }
        with patch.object(mail_provider.domain_health_tracker, "record") as record:
            mail_provider.mark_mailbox_result(
                mailbox,
                success=False,
                error="registration_disallowed",
                mail_config=mail_config,
            )

        record.assert_called_once_with(
            mailbox,
            success=False,
            error="registration_disallowed",
            policy=mail_config["domain_health"],
        )

    def test_stats_write_failure_does_not_fail_registration_result(self):
        mailbox = {
            "provider": "freemail",
            "provider_ref": "freemail#stable-id",
            "address": "user@example.com",
        }
        with patch.object(mail_provider.domain_health_tracker, "record", side_effect=OSError("disk full")):
            mail_provider.mark_mailbox_result(mailbox, success=True, mail_config={})

    def test_health_domain_uses_configured_base_for_generated_subdomain(self):
        mailbox = {"address": "user@random.sub.base.example"}
        provider = SimpleNamespace(domain=["base.example"], default_domain="")

        mail_provider._assign_health_domain(mailbox, provider)

        self.assertEqual(mailbox["health_domain"], "base.example")

    def test_provider_ref_uses_persisted_provider_id(self):
        entries = mail_provider._entries(
            {
                "providers": [
                    {
                        "provider_id": "stable-id",
                        "enable": True,
                        "type": "freemail",
                    }
                ]
            }
        )

        self.assertEqual(entries[0]["provider_ref"], "freemail#stable-id")

    def test_outlook_pool_skips_auto_disabled_domain_and_uses_next_credential(self):
        provider = mail_provider.OutlookTokenProvider.__new__(mail_provider.OutlookTokenProvider)
        provider.provider_ref = "outlook_token#stable-id"
        provider.label = "Outlook"
        provider.domain_health_enabled = True
        provider.pool = [
            {"email": "first@bad.example", "password": "", "client_id": "client-1", "refresh_token": "refresh-1"},
            {"email": "second@good.example", "password": "", "client_id": "client-2", "refresh_token": "refresh-2"},
        ]
        with patch.object(mail_provider, "_load_outlook_token_state", return_value={}), patch.object(
            mail_provider,
            "_save_outlook_token_state",
        ), patch.object(
            mail_provider.domain_health_tracker,
            "is_disabled",
            side_effect=lambda _provider_ref, domain: domain == "bad.example",
        ):
            mailbox = provider.create_mailbox()

        self.assertEqual(mailbox["address"], "second@good.example")


if __name__ == "__main__":
    unittest.main()
