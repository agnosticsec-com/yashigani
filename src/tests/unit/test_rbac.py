"""Unit tests for yashigani.rbac.model and yashigani.rbac.store."""
from __future__ import annotations
import pytest
from yashigani.rbac.model import RBACGroup, ResourcePattern, RateLimitOverride


def _matches(pattern: ResourcePattern, method: str, path: str) -> bool:
    """Call the store-level matching helpers since ResourcePattern has no .matches() method."""
    from yashigani.rbac.store import _method_matches, _path_matches
    return _method_matches(pattern.method, method) and _path_matches(pattern.path_glob, path)


class TestResourcePattern:
    def test_exact_match(self):
        p = ResourcePattern(method="GET", path_glob="/tools/list")
        assert _matches(p, "GET", "/tools/list")
        assert not _matches(p, "POST", "/tools/list")
        assert not _matches(p, "GET", "/tools/call")

    def test_wildcard_method(self):
        p = ResourcePattern(method="*", path_glob="/tools/list")
        assert _matches(p, "GET", "/tools/list")
        assert _matches(p, "POST", "/tools/list")
        assert _matches(p, "DELETE", "/tools/list")

    def test_double_star_glob(self):
        p = ResourcePattern(method="*", path_glob="**")
        assert _matches(p, "GET", "/anything")
        assert _matches(p, "POST", "/deep/nested/path")

    def test_prefix_glob(self):
        p = ResourcePattern(method="*", path_glob="/tools/**")
        assert _matches(p, "GET", "/tools/list")
        assert _matches(p, "POST", "/tools/call/foo")
        assert not _matches(p, "GET", "/resources/list")

    def test_to_dict_roundtrip(self):
        p = ResourcePattern(method="GET", path_glob="/tools/**")
        d = p.to_dict()
        assert d["method"] == "GET"
        assert d["path_glob"] == "/tools/**"


class TestRBACGroup:
    def test_creation_defaults(self):
        g = RBACGroup(id="g1", display_name="Test Group")
        assert g.members == set()
        assert g.allowed_resources == []
        assert g.rate_limit_override is None

    def test_member_management(self):
        g = RBACGroup(id="g1", display_name="Test")
        g.members.add("user@example.com")
        assert "user@example.com" in g.members

    def test_rate_limit_override_to_dict(self):
        override = RateLimitOverride(per_session_rps=10.0, per_session_burst=20)
        d = override.to_dict()
        assert d["per_session_rps"] == 10.0
        assert d["per_session_burst"] == 20


class TestRBACStore:
    def test_add_and_get_group(self, mock_redis):
        from yashigani.rbac.store import RBACStore
        store = RBACStore(redis_client=mock_redis)
        group = RBACGroup(id="g1", display_name="Engineers",
                          allowed_resources=[ResourcePattern(method="*", path_glob="**")])
        store.add_group(group)
        retrieved = store.get_group("g1")
        assert retrieved is not None
        assert retrieved.display_name == "Engineers"

    def test_list_groups_empty(self, mock_redis):
        from yashigani.rbac.store import RBACStore
        store = RBACStore(redis_client=mock_redis)
        assert store.list_groups() == []

    def test_remove_group(self, mock_redis):
        from yashigani.rbac.store import RBACStore
        store = RBACStore(redis_client=mock_redis)
        group = RBACGroup(id="g1", display_name="Test")
        store.add_group(group)
        store.remove_group("g1")
        assert store.get_group("g1") is None

    def test_add_member(self, mock_redis):
        from yashigani.rbac.store import RBACStore
        store = RBACStore(redis_client=mock_redis)
        group = RBACGroup(id="g1", display_name="Test")
        store.add_group(group)
        store.add_member("g1", "alice@example.com")
        updated = store.get_group("g1")
        assert "alice@example.com" in updated.members

    def test_get_user_groups(self, mock_redis):
        from yashigani.rbac.store import RBACStore
        store = RBACStore(redis_client=mock_redis)
        g1 = RBACGroup(id="g1", display_name="Group1", members={"alice@example.com"})
        g2 = RBACGroup(id="g2", display_name="Group2", members={"bob@example.com"})
        store.add_group(g1)
        store.add_group(g2)
        groups = store.get_user_groups("alice@example.com")
        assert len(groups) == 1
        assert groups[0].id == "g1"

    def test_get_nonexistent_group_returns_none(self, mock_redis):
        from yashigani.rbac.store import RBACStore
        store = RBACStore(redis_client=mock_redis)
        assert store.get_group("nonexistent") is None

    def test_to_opa_document(self, mock_redis):
        from yashigani.rbac.store import RBACStore
        store = RBACStore(redis_client=mock_redis)
        g = RBACGroup(id="g1", display_name="Eng",
                      allowed_resources=[ResourcePattern(method="GET", path_glob="/tools/**")],
                      members={"user@example.com"})
        store.add_group(g)
        doc = store.to_opa_document()
        assert "groups" in doc
        assert "user_groups" in doc
        assert "user@example.com" in doc["user_groups"]
