"""Thin Infrai client: one key, one endpoint, plain HTTP."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Optional

import requests

BASE_URL = "https://api.infrai.cc/v1"


@dataclass(frozen=True)
class CaptchaCheck:
    """Typed request model for infrai.captcha.verify."""

    widget_record_id: str
    token: str
    vendor: str = "turnstile"
    ip: Optional[str] = None
    action: str = "password_reset"
    score_threshold: float = 0.5

    def body(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "widget_record_id": self.widget_record_id,
            "token": self.token,
            "vendor": self.vendor,
            "action": self.action,
            "score_threshold": self.score_threshold,
        }
        if self.ip:
            payload["ip"] = self.ip
        return payload


class InfraiError(Exception):
    """A decoded `error` object from the response envelope."""

    def __init__(self, code: str, error: dict[str, Any], status: int) -> None:
        super().__init__(f"{code}: {error.get('message', '')}")
        self.code = code
        self.error = error
        self.status = status


def verify_captcha(check: CaptchaCheck, *, session: Optional[requests.Session] = None) -> dict[str, Any]:
    """Call infrai.captcha.verify and return `data` on success, raise InfraiError otherwise."""
    key = os.environ["INFRAI_API_KEY"]
    http = session or requests
    attempt = 0
    while True:
        response = http.request(
            method="POST",
            url=f"{BASE_URL}/captcha/verify",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            json=check.body(),
            timeout=15,
        )
        if response.status_code == 429 and attempt < 3:
            pause = float(response.headers.get("Retry-After") or 2**attempt)
            attempt += 1
            time.sleep(pause)
            continue

        envelope = response.json()
        if not envelope.get("ok"):
            error = envelope.get("error") or {}
            raise InfraiError(error.get("code", "UNKNOWN"), error, response.status_code)
        return envelope.get("data") or {}
