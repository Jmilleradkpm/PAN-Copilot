"""Tests for the PAN-OS config hygiene checks."""
from checks.engine import Severity, run_checks


XML_CONFIG = """
<config>
  <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
    <rulebase><security><rules>
      <entry name="web-out">
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>10.0.0.0/24</member></source>
        <destination><member>any</member></destination>
        <application><member>ssl</member></application>
        <service><member>application-default</member></service>
        <action>allow</action>
        <log-end>yes</log-end>
        <profile-setting><group><member>default</member></group></profile-setting>
      </entry>
      <entry name="allow-any">
        <from><member>any</member></from>
        <to><member>any</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>allow</action>
      </entry>
      <entry name="old-rule">
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <action>allow</action>
        <disabled>yes</disabled>
      </entry>
    </rules></security></rulebase>
  </entry></vsys></entry></devices>
</config>
"""


def _cats(result):
    return {f.category for f in result.findings}


def test_detects_any_any_rule():
    result = run_checks(XML_CONFIG)
    assert result.source_format == "xml"
    assert result.rule_count == 3
    assert "any-any-rule" in _cats(result)


def test_flags_missing_profiles_on_allow():
    result = run_checks(XML_CONFIG)
    profile_findings = [f for f in result.findings if f.category == "no-security-profiles"]
    # allow-any has no profiles; web-out has a group → only allow-any flagged.
    assert any(f.rule == "allow-any" for f in profile_findings)
    assert not any(f.rule == "web-out" for f in profile_findings)


def test_well_configured_rule_not_over_flagged():
    result = run_checks(XML_CONFIG)
    web_findings = [f for f in result.findings if f.rule == "web-out"]
    # web-out is scoped, logged, profiled → should be clean.
    assert web_findings == []


def test_disabled_rule_flagged_info():
    result = run_checks(XML_CONFIG)
    disabled = [f for f in result.findings if f.category == "disabled-rule"]
    assert len(disabled) == 1
    assert disabled[0].severity == Severity.INFO


def test_shadowing_detected():
    cfg = """
    <config><rulebase><security><rules>
      <entry name="broad">
        <from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>allow</action>
        <profile-setting><group><member>g</member></group></profile-setting>
      </entry>
      <entry name="specific">
        <from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>10.0.0.5</member></source><destination><member>8.8.8.8</member></destination>
        <application><member>dns</member></application><service><member>any</member></service>
        <action>allow</action>
        <profile-setting><group><member>g</member></group></profile-setting>
      </entry>
    </rules></security></rulebase></config>
    """
    result = run_checks(cfg)
    shadow = [f for f in result.findings if f.category == "shadowed-rule"]
    assert len(shadow) == 1
    assert shadow[0].rule == "specific"


def test_set_format_parsing():
    cfg = (
        'set rulebase security rules "allow-all" from any\n'
        'set rulebase security rules "allow-all" to any\n'
        'set rulebase security rules "allow-all" source any\n'
        'set rulebase security rules "allow-all" destination any\n'
        'set rulebase security rules "allow-all" application any\n'
        'set rulebase security rules "allow-all" service any\n'
        'set rulebase security rules "allow-all" action allow\n'
    )
    result = run_checks(cfg)
    assert result.source_format == "set"
    assert result.rule_count == 1
    assert "any-any-rule" in _cats(result)


def test_empty_config():
    result = run_checks("not a config at all")
    assert result.rule_count == 0
    assert result.findings == []
