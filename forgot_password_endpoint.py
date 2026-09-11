"""Runnable end-to-end pass: one forgot-password request, start to decision."""

from __future__ import annotations

import json
import sys
from typing import Optional

from infrai_captcha import CaptchaCheck, InfraiError, verify_captcha
from reset_gate import Member, ResetRequest, ResetDecision, decide

DIRECTORY = {
    ("acme", "dana@acme.example"): Member("dana@acme.example", "acme", "active"),
    ("acme", "leo@acme.example"): Member("leo@acme.example", "acme", "suspended"),
}


def lookup(request: ResetRequest) -> Optional[Member]:
    return DIRECTORY.get((request.tenant_id, request.email))


def handle(request: ResetRequest) -> ResetDecision:
    """Verify the challenge, then decide. A declined challenge is a 400 to your caller."""
    try:
        data = verify_captcha(
            CaptchaCheck(
                widget_record_id=request.widget_record_id,
                token=request.captcha_token,
                ip=request.ip,
                action="password_reset",
            )
        )
    except InfraiError as err:
        return ResetDecision("captcha_rejected", 400, reason=err.code)

    return decide(request, lookup(request), captcha_passed=bool(data.get("success")))


def main() -> int:
    token = sys.argv[1] if len(sys.argv) > 1 else ""
    email = sys.argv[2] if len(sys.argv) > 2 else "dana@acme.example"
    widget_record_id = sys.argv[3] if len(sys.argv) > 3 else ""
    decision = handle(
        ResetRequest(
            email=email,
            tenant_id="acme",
            captcha_token=token,
            widget_record_id=widget_record_id,
        )
    )
    print(json.dumps({
        "outcome": decision.outcome,
        "http_status": decision.http_status,
        "expires_at": decision.expires_at,
        "email_sent": decision.outcome == "issued",
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
