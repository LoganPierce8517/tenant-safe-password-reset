"""The decision a forgot-password endpoint actually has to make."""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from typing import Literal, Optional

Outcome = Literal["issued", "captcha_rejected", "suspended", "silent"]

TOKEN_TTL_SECONDS = 900


@dataclass(frozen=True)
class ResetRequest:
    """Typed request model for POST /password/forgot on your own service."""

    email: str
    tenant_id: str
    captcha_token: str
    ip: Optional[str] = None
    widget_record_id: str = ""


@dataclass(frozen=True)
class Member:
    """What your tenant directory knows about the address."""

    email: str
    tenant_id: str
    status: Literal["active", "invited", "suspended"]


@dataclass(frozen=True)
class ResetDecision:
    outcome: Outcome
    http_status: int
    reset_token: Optional[str] = None
    expires_at: Optional[int] = None
    reason: Optional[str] = None


def sign_reset_token(email: str, tenant_id: str, issued_at: int, secret: Optional[str] = None) -> str:
    secret = secret or os.environ["RESET_TOKEN_SECRET"]
    message = f"{tenant_id}:{email}:{issued_at}".encode()
    digest = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return f"{issued_at}.{digest}"


def decide(
    request: ResetRequest,
    member: Optional[Member],
    captcha_passed: bool,
    *,
    now: Optional[int] = None,
    secret: Optional[str] = None,
) -> ResetDecision:
    """Captcha first, then account lifecycle, then a uniform answer to the caller.

    Unknown and suspended addresses both get HTTP 202 with no token: an attacker
    cannot use this endpoint to enumerate who belongs to a tenant.
    """
    if not captcha_passed:
        return ResetDecision("captcha_rejected", 400, reason="captcha_declined")

    if member is None or member.tenant_id != request.tenant_id:
        return ResetDecision("silent", 202, reason="no_such_member")

    if member.status == "suspended":
        return ResetDecision("suspended", 202, reason="account_suspended")

    issued_at = int(now if now is not None else time.time())
    return ResetDecision(
        outcome="issued",
        http_status=202,
        reset_token=sign_reset_token(member.email, member.tenant_id, issued_at, secret),
        expires_at=issued_at + TOKEN_TTL_SECONDS,
    )
