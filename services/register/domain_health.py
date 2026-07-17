from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services.config import DATA_DIR


DEFAULT_DOMAIN_HEALTH_POLICY = {
    "enabled": True,
    "min_samples": 5,
    "min_success_rate": 20.0,
}


def normalize_policy(value: dict | None) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    return {
        "enabled": bool(source.get("enabled", DEFAULT_DOMAIN_HEALTH_POLICY["enabled"])),
        "min_samples": max(1, int(source.get("min_samples") or DEFAULT_DOMAIN_HEALTH_POLICY["min_samples"])),
        "min_success_rate": min(
            100.0,
            max(0.0, float(source.get("min_success_rate", DEFAULT_DOMAIN_HEALTH_POLICY["min_success_rate"]))),
        ),
    }


def mailbox_domain(mailbox: dict) -> str:
    base_domain = str(mailbox.get("base_domain") or mailbox.get("health_domain") or "").strip().lower().lstrip("@")
    if base_domain:
        return base_domain
    address = str(mailbox.get("address") or "").strip().lower()
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().lstrip("@")


class DomainHealthTracker:
    """持久化 provider/domain 注册成功率，并维护自动停用状态。"""

    def __init__(self, store_file: Path):
        self.store_file = Path(store_file)
        self._lock = threading.RLock()

    @staticmethod
    def _key(provider_ref: str, domain: str) -> str:
        return f"{str(provider_ref).strip().lower()}|{str(domain).strip().lower()}"

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.store_file.read_text(encoding="utf-8"))
        except Exception:
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(key): dict(value) for key, value in data.items() if isinstance(value, dict)}

    def _save(self, state: dict[str, dict[str, Any]]) -> None:
        self.store_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file = self.store_file.with_suffix(f"{self.store_file.suffix}.tmp")
        temp_file.write_text(
            json.dumps({key: state[key] for key in sorted(state)}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temp_file.replace(self.store_file)

    def record(
        self,
        mailbox: dict,
        *,
        success: bool,
        error: Exception | str | None = None,
        policy: dict | None = None,
    ) -> dict[str, Any] | None:
        provider = str(mailbox.get("provider") or "").strip()
        provider_ref = str(mailbox.get("provider_ref") or provider).strip()
        domain = mailbox_domain(mailbox)
        if not provider_ref or not domain:
            return None
        normalized_policy = normalize_policy(policy)
        key = self._key(provider_ref, domain)
        with self._lock:
            state = self._load()
            previous = state.get(key) if isinstance(state.get(key), dict) else {}
            success_count = int(previous.get("success") or 0) + (1 if success else 0)
            fail_count = int(previous.get("fail") or 0) + (0 if success else 1)
            attempts = success_count + fail_count
            success_rate = round(success_count * 100.0 / max(1, attempts), 1)
            disabled = bool(previous.get("disabled")) or bool(
                normalized_policy["enabled"]
                and attempts >= normalized_policy["min_samples"]
                and success_rate < normalized_policy["min_success_rate"]
            )
            row = {
                "provider": provider,
                "provider_ref": provider_ref,
                "domain": domain,
                "attempts": attempts,
                "success": success_count,
                "fail": fail_count,
                "success_rate": success_rate,
                "disabled": disabled,
                "last_error": "" if success else str(error or "")[:300],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            state[key] = row
            self._save(state)
            return dict(row)

    def is_disabled(self, provider_ref: str, domain: str) -> bool:
        key = self._key(provider_ref, domain)
        with self._lock:
            row = self._load().get(key)
        return bool(row.get("disabled")) if isinstance(row, dict) else False

    def filter_domains(self, provider_ref: str, domains: list[str]) -> list[str]:
        ref = str(provider_ref or "").strip().lower()
        with self._lock:
            state = self._load()
        disabled = {
            str(row.get("domain") or "").strip().lower()
            for row in state.values()
            if str(row.get("provider_ref") or "").strip().lower() == ref and bool(row.get("disabled"))
        }
        return [
            str(domain).strip()
            for domain in domains
            if str(domain).strip() and str(domain).strip().lower().lstrip("*.") not in disabled
        ]

    def provider_fully_disabled(self, provider_ref: str) -> bool:
        ref = str(provider_ref or "").strip().lower()
        if not ref:
            return False
        with self._lock:
            rows = [row for row in self._load().values() if str(row.get("provider_ref") or "").strip().lower() == ref]
        return bool(rows) and all(bool(row.get("disabled")) for row in rows)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = [dict(row) for row in self._load().values()]
        return sorted(rows, key=lambda row: (str(row.get("provider_ref") or ""), str(row.get("domain") or "")))

    def reset(self) -> int:
        with self._lock:
            count = len(self._load())
            self._save({})
        return count


domain_health_tracker = DomainHealthTracker(DATA_DIR / "register_domain_health.json")
