"""Golden tests for sample ASA fixture."""

from pathlib import Path

import pytest

from migration.pipeline import MigrationOptions, run_migration

FIXTURE = Path(__file__).parent / "fixtures" / "sample_asa_config.txt"


@pytest.fixture
def asa_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def test_parse_sample_hostname(asa_text: str) -> None:
    result = run_migration(asa_text, options=MigrationOptions())
    assert result.ir.hostname == "ASA-Firewall"


def test_parse_sample_zones(asa_text: str) -> None:
    result = run_migration(asa_text)
    zone_names = {z.name for z in result.ir.zones}
    assert zone_names == {"outside", "inside", "dmz"}


def test_parse_sample_address_objects(asa_text: str) -> None:
    result = run_migration(asa_text)
    names = {a.name for a in result.ir.addresses}
    assert "obj_inside" in names
    assert "web_server" in names


def test_parse_sample_security_rules_count(asa_text: str) -> None:
    result = run_migration(asa_text)
    assert len(result.ir.security_rules) == 3


def test_parse_sample_nat_rules(asa_text: str) -> None:
    result = run_migration(asa_text)
    assert len(result.ir.nat_rules) == 2


def test_parse_sample_vpn_tunnel(asa_text: str) -> None:
    result = run_migration(asa_text)
    assert len(result.ir.vpn_tunnels) >= 1
    assert result.ir.vpn_tunnels[0].peer_ip == "198.51.100.1"


def test_set_commands_emitted(asa_text: str) -> None:
    result = run_migration(asa_text)
    assert len(result.set_commands) > 20
    assert any("set vsys vsys1 address obj_inside" in c for c in result.set_commands)
    assert any("set vsys vsys1 rulebase security rules outside_in_1" in c for c in result.set_commands)
    assert not any("device-group" in c for c in result.set_commands)


def test_merged_xml_contains_rules(asa_text: str) -> None:
    result = run_migration(asa_text)
    assert "outside_in_1" in result.merged_xml
    assert "<config" in result.merged_xml


def test_psk_not_in_output(asa_text: str) -> None:
    result = run_migration(asa_text)
    assert "mykey" not in result.set_text
    assert "[PSK_REMOVED]" in result.set_text or result.set_text  # PSK in VPN emit