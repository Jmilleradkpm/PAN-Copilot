"""Vendor detection tests."""

from migration.detect import VendorFormat, detect_vendor, vendor_family


def test_detect_asa() -> None:
    text = "object network foo\n host 1.2.3.4\naccess-list outside_in extended permit ip any any"
    fmt, _ = detect_vendor(text)
    assert fmt == VendorFormat.CISCO_ASA
    assert vendor_family(fmt) == "cisco"


def test_detect_checkpoint() -> None:
    text = 'add host name "x" ip-address 1.2.3.4\nadd access-rule name "r" action Accept'
    fmt, _ = detect_vendor(text)
    assert fmt == VendorFormat.CHECKPOINT_R80
    assert vendor_family(fmt) == "checkpoint"


def test_detect_fortinet() -> None:
    text = "config firewall policy\n    edit 1\n        set action accept"
    fmt, _ = detect_vendor(text)
    assert fmt == VendorFormat.FORTINET


def test_detect_junos() -> None:
    text = "security {\n  policies {\n    from-zone trust to-zone untrust {"
    fmt, _ = detect_vendor(text)
    assert fmt == VendorFormat.JUNOS


def test_override_checkpoint() -> None:
    text = "object network foo"
    fmt, _ = detect_vendor(text, "checkpoint")
    assert fmt == VendorFormat.CHECKPOINT_R80