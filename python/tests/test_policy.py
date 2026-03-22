"""Tests for SimplePolicy Datalog generation."""

from aip_token.policy import SimplePolicy


def test_simple_tool_allowlist():
    p = SimplePolicy(tools=["search", "browse"])
    dl = p.to_datalog()
    assert 'check if tool($tool), ["search", "browse"].contains($tool)' in dl


def test_simple_budget():
    p = SimplePolicy(budget_cents=50)
    dl = p.to_datalog()
    assert "check if budget($b), $b <= 50" in dl


def test_simple_full():
    p = SimplePolicy(tools=["search"], budget_cents=100, max_depth=3, ttl_seconds=3600)
    dl = p.to_datalog()
    assert "tool($tool)" in dl
    assert "budget($b)" in dl
    assert "depth($d)" in dl
    assert "time($t)" in dl


def test_simple_empty():
    p = SimplePolicy()
    assert p.to_datalog() == ""
