"""Migration pipeline tests for non-Cisco vendors."""

from pathlib import Path

import pytest

from migration.pipeline import MigrationOptions, run_migration

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def checkpoint_text() -> str:
    return (FIXTURES / "sample_checkpoint_config.txt").read_text(encoding="utf-8")


@pytest.fixture
def fortinet_text() -> str:
    return (FIXTURES / "sample_fortinet_config.txt").read_text(encoding="utf-8")


@pytest.fixture
def junos_text() -> str:
    return (FIXTURES / "sample_junos_config.txt").read_text(encoding="utf-8")


def test_checkpoint_addresses_and_rules(checkpoint_text: str) -> None:
    result = run_migration(checkpoint_text, options=MigrationOptions(source_vendor="checkpoint"))
    assert result.ir.source_vendor == "checkpoint"
    names = {a.name for a in result.ir.addresses}
    assert "Server1" in names
    assert "Internal" in names
    assert len(result.ir.security_rules) >= 1
    assert any("set vsys vsys1" in c for c in result.set_commands)


def test_fortinet_policy(fortinet_text: str) -> None:
    result = run_migration(fortinet_text)
    assert result.ir.source_vendor == "fortinet"
    assert "lan_net" in {a.name for a in result.ir.addresses}
    assert len(result.ir.security_rules) == 1
    assert result.ir.security_rules[0].from_zones == ["port1"]


def test_junos_policy(junos_text: str) -> None:
    result = run_migration(junos_text)
    assert result.ir.source_vendor == "juniper"
    assert "inside_net" in {a.name for a in result.ir.addresses}
    assert len(result.ir.security_rules) == 1
    assert result.ir.security_rules[0].from_zones == ["trust"]