from __future__ import annotations

"""email-forensics Cell — tests."""

from plugin import EmailForensicsPlugin


def test_plugin_registers_tools():
    plugin = EmailForensicsPlugin()
    tools = plugin.register_tools()
    assert len(tools) >= 1
    assert all(t.name for t in tools)
    assert all(t.domain for t in tools)
    assert all(t.risk_level in ("LOW", "MEDIUM", "HIGH") for t in tools)


def test_plugin_metadata():
    plugin = EmailForensicsPlugin()
    assert plugin.name == "email-forensics"
    assert plugin.version
    assert plugin.domain == "forensics"
