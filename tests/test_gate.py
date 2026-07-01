"""Gojo boundary gate — enforces role + source-class boundaries, not just throttling."""

from ghosted.gate import GojoBoundaryGate


def _decide(g, **kw):
    v = g.evaluate_request(**kw)
    return v["decision"], v.get("reason")


def test_operator_from_internal_may_drive_wireguard():
    g = GojoBoundaryGate()
    assert _decide(g, actor_role="operator", action="wireguard_connect",
                   source_class="internal") == ("allow", "ok")


def test_remote_web_visitor_cannot_drive_wireguard_role_boundary():
    g = GojoBoundaryGate()
    assert _decide(g, actor_role="anonymous_web", action="wireguard_connect",
                   source_class="internal") == ("deny", "role_not_permitted")


def test_operator_from_remote_network_cannot_drive_wireguard_source_boundary():
    g = GojoBoundaryGate()
    assert _decide(g, actor_role="operator", action="wireguard_connect",
                   source_class="network_remote") == ("deny", "source_not_permitted")


def test_homepage_get_allowed_for_remote_web_visitor():
    g = GojoBoundaryGate()
    assert _decide(g, actor_role="anonymous_web", action="homepage_get",
                   source_class="network_remote") == ("allow", "ok")


def test_unknown_role_denied_on_homepage():
    g = GojoBoundaryGate()
    assert _decide(g, actor_role="stranger", action="homepage_get",
                   source_class="network_remote") == ("deny", "role_not_permitted")


def test_unpoliced_action_is_only_throttled_not_boundary_denied():
    g = GojoBoundaryGate()
    # an action with no policy entry has no role/source boundary — it is allowed
    assert _decide(g, actor_role="whoever", action="some_other_action",
                   source_class="anywhere") == ("allow", "ok")


def test_boundary_denies_before_throttle_counts():
    g = GojoBoundaryGate()
    # 200 denied role attempts must not consume the throttle bucket (they never count)
    for _ in range(200):
        d, r = _decide(g, actor_role="anonymous_web", action="wireguard_enroll",
                       source_class="internal")
        assert (d, r) == ("deny", "role_not_permitted")
