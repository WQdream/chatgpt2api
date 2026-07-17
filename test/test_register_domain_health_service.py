import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from services.register_service import RegisterService


class RegisterDomainHealthServiceTests(unittest.TestCase):
    def test_get_exposes_policy_and_domain_statistics(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "services.register_service.domain_health_tracker.snapshot",
            return_value=[{"provider_ref": "fixture#1", "domain": "example.com", "success_rate": 50.0}],
        ):
            service = RegisterService(Path(directory) / "register.json")
            result = service.get()

        self.assertTrue(result["domain_health"]["policy"]["enabled"])
        self.assertEqual(result["domain_health"]["domains"][0]["domain"], "example.com")

    def test_reset_domain_health_clears_tracker(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "services.register_service.domain_health_tracker.reset",
            return_value=4,
        ) as reset, patch(
            "services.register_service.domain_health_tracker.snapshot",
            return_value=[],
        ):
            service = RegisterService(Path(directory) / "register.json")
            result = service.reset_domain_health()

        reset.assert_called_once_with()
        self.assertEqual(result["domain_health"]["domains"], [])


if __name__ == "__main__":
    unittest.main()
