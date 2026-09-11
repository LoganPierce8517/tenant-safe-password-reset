from reset_gate import Member, ResetRequest, decide, sign_reset_token

SECRET = "test-secret"


def req(email="dana@acme.example", tenant="acme"):
    return ResetRequest(email=email, tenant_id=tenant, captcha_token="tok", ip="203.0.113.9")


def test_active_member_gets_a_token_that_expires():
    member = Member("dana@acme.example", "acme", "active")
    d = decide(req(), member, captcha_passed=True, now=1_700_000_000, secret=SECRET)
    assert d.outcome == "issued"
    assert d.http_status == 202
    assert d.reset_token == sign_reset_token("dana@acme.example", "acme", 1_700_000_000, SECRET)
    assert d.expires_at == 1_700_000_900


def test_suspended_and_unknown_look_identical_from_outside():
    suspended = decide(
        req("leo@acme.example"),
        Member("leo@acme.example", "acme", "suspended"),
        captcha_passed=True,
        now=1_700_000_000,
        secret=SECRET,
    )
    unknown = decide(req("nobody@acme.example"), None, captcha_passed=True, now=1_700_000_000, secret=SECRET)
    assert (suspended.http_status, suspended.reset_token) == (202, None)
    assert (unknown.http_status, unknown.reset_token) == (202, None)


def test_member_of_another_tenant_is_not_reachable():
    other = Member("dana@acme.example", "globex", "active")
    d = decide(req(), other, captcha_passed=True, now=1_700_000_000, secret=SECRET)
    assert d.outcome == "silent"
    assert d.reset_token is None


def test_declined_challenge_never_reaches_the_directory():
    d = decide(req(), Member("dana@acme.example", "acme", "active"), captcha_passed=False, secret=SECRET)
    assert (d.outcome, d.http_status, d.reset_token) == ("captcha_rejected", 400, None)
