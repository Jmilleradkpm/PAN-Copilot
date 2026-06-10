# KB-CORTEX-XDR-001 — Cortex XDR / XSIAM: Alert Grouping, Network Location, Broker VM & Cloud Identity Engine

**Article ID:** KB-CORTEX-XDR-001  
**Products:** Cortex XDR, Cortex XSIAM  
**Components:** XDR Agent, Broker VM, Cloud Identity Engine, Panorama, Cortex Gateway  
**Audience:** SOC Analysts, Detection Engineers, Endpoint Administrators, Platform Engineers  
**Revision:** 1.0 — May 2026

---

> **CORE PRINCIPLE:** Cortex XDR and XSIAM correlate based on observable entities and artifacts. A shared artifact is not automatically a shared attack. NAT, proxy, VPN, and shared resolver IPs must be treated as **weak evidence** unless stronger indicators co-exist.

---

## Table of Contents

1. [Operating Model and Platform Overview](#1-operating-model-and-platform-overview)
2. [Alert Grouping and Incident Noise](#2-alert-grouping-and-incident-noise)
   - 2.1 Root Cause: NAT and Shared Egress IPs
   - 2.2 High-Noise Artifact Reference
   - 2.3 Tuning Alert Grouping Rules
   - 2.4 Grouping Rule Precedence
   - 2.5 Diagnostic Workflow
   - 2.6 Remediation and Design Guidance
3. [Network Location Configuration](#3-network-location-configuration)
   - 3.1 How Network Location Detection Works
   - 3.2 GlobalProtect Split-Tunnel Interaction
   - 3.3 Misconfiguration Patterns
   - 3.4 Diagnostic Workflow
   - 3.5 Resolution Paths
4. [Broker VM Syslog vs. Native Integrations](#4-broker-vm-syslog-vs-native-integrations)
   - 4.1 Path Comparison
   - 4.2 When to Use Each Method
   - 4.3 Common Syslog Issues
   - 4.4 Dataset Naming and Normalization
5. [Dataset Schema and XQL Field Reference](#5-dataset-schema-and-xql-field-reference)
   - 5.1 palo_alto_* Dataset Reference
   - 5.2 XDM Field Mapping Pitfalls
   - 5.3 Cross-Dataset Join Example
6. [Cloud Identity Engine Activation](#6-cloud-identity-engine-activation)
   - 6.1 Activation Requirements and Hub Role Mapping
   - 6.2 Common Failure States
   - 6.3 Remediation Workflow
   - 6.4 Post-Activation Validation
7. [SOC Runbook](#7-soc-runbook)
8. [Engineering Runbook](#8-engineering-runbook)
9. [Preventive Design Standards](#9-preventive-design-standards)
10. [Escalation Criteria](#10-escalation-criteria)
11. [Final Resolution Checklists](#11-final-resolution-checklists)
12. [Quick Reference Matrix](#12-quick-reference-matrix)

---

## 1. Operating Model and Platform Overview

Cortex XDR and Cortex XSIAM receive events, extract entities, map those events into datasets, correlate related activity, and raise alerts or incidents when detection logic is satisfied. The correlation engine evaluates relationships between artifacts, entities, exact-match detections, and time windows — it does not directly judge intent.

Incident correlation uses artifact and entity relationships. This is helpful when the artifact represents a real relationship (same endpoint, same user, same file hash, same process chain). It becomes **problematic** when the artifact is a shared infrastructure value such as a NAT IP, proxy IP, shared VPN egress address, or load balancer frontend.

> **INFO — XSIAM vs XDR:** XSIAM extends XDR with additional SIEM capabilities, custom YAML-based Correlation Rules, broader data source ingestion, and an integrated SOAR layer. Many platform behaviors in this article apply to both products; XSIAM-specific differences are called out explicitly.

---

## 2. Alert Grouping and Incident Noise

Cortex XDR and XSIAM group alerts into incidents using causality analysis, shared indicators, and configurable grouping rules. When endpoints share infrastructure — particularly outbound NAT or a common egress IP — the stitching logic can pull unrelated alerts from different hosts into a single incident, creating a misleading blast radius and inflating analyst workload.

### 2.1 Root Cause: NAT and Shared Egress IPs

The most common SOC complaint is incidents auto-grouping alerts from unrelated endpoints because all traffic exits through the same NAT pool or proxy IP. XDR/XSIAM uses network indicators (`dest_ip`, `src_ip`, domains) as one correlation axis. When these values match across multiple endpoints, the correlator treats them as shared artifacts and merges the incidents.

> **CRITICAL:** The incident stitching engine does **not** distinguish between an IP that belongs to an endpoint versus one that is merely a shared transit point (NAT gateway, proxy, load balancer). A high-throughput NAT IP can appear in hundreds of alerts per hour, becoming an inadvertent grouping magnet.

### 2.2 High-Noise Artifact Reference

The following artifact types commonly cause false grouping and should be treated as **weak evidence**:

- Public NAT egress IP
- GlobalProtect egress IP
- Prisma Access egress IP
- Proxy egress IP (Secure Web Gateway)
- Shared VDI source IP
- Terminal server source IP
- Cloud workload NAT gateway IP
- Load balancer frontend IP
- Firewall outside interface IP
- Shared DNS resolver IP
- Shared mail relay IP

| Artifact Type | Grouping Strength | Action |
|---|---|---|
| Same endpoint ID | **Strong** | Keep grouped |
| Same endpoint + same user | **Strong** | Keep grouped |
| Same process causality chain | **Strong** | Keep grouped |
| Same file hash on multiple hosts | **Strong** | Keep grouped |
| Same rare destination + same behavior | **Strong** | Keep grouped |
| Same public egress IP | **Weak** | Exclude from grouping rules |
| Same NAT pool | **Weak** | Add to Network Exclusions |
| Same proxy / VPN gateway | **Weak** | Add to Network Exclusions |
| Same DNS resolver | **Weak** | Exclude from grouping rules |

### 2.3 Tuning Alert Grouping Rules

Navigate to:
- **XDR:** `Settings > Incident Management > Alert Grouping`
- **XSIAM:** `Settings > Alert & Incident Configuration > Grouping Rules`

Rules evaluate in order; the first match wins.

**Step 1 — Identify the shared IP(s):**

Run this XQL query against `xdr_alerts` to find high-cardinality destination IPs appearing across many endpoint IDs:

```xql
-- XQL: Find grouping magnets (top shared IPs driving cross-host grouping)
dataset = xdr_alerts
| fields actor_primary_username, action_remote_ip, alert_id, endpoint_id
| where action_remote_ip != null
| comp count(endpoint_id) as endpoint_count, count(alert_id) as alert_count by action_remote_ip
| filter endpoint_count > 5
| sort desc endpoint_count
| limit 20
```

> **TIP:** Addresses appearing with high `endpoint_count` and low expected correlation — RFC 1918 ranges, known proxies, CDN CIDRs — are candidates for exclusion from grouping rules.

**Step 2 — Create an Exclude from grouping rule:**

Under **Matching Criteria**, set `dest_ip` or `src_ip` to your NAT pool CIDR and set the action to **Do not use this indicator for grouping**.

**Step 3 — Raise similarity threshold (optional):**

Increase the minimum similarity threshold for alerts sharing only an IP indicator (no shared process tree, user, or causality). The default is aggressive; raising it to 80–90 reduces cross-host grouping.

**Step 4 — Add to Network Exclusions:**

Add internal RFC 1918 ranges and known NAT/proxy CIDRs to the Network Exclusions list under `Settings > Network Configuration`. IPs on this list are stripped from grouping consideration entirely.

**Step 5 — Validate with Grouping Preview:**

Submit a recent alert pair that incorrectly merged and confirm the revised rules separate them.

> **INFO — XSIAM:** In XSIAM, custom Correlation Rules (YAML-based) create incidents independently of grouping rules. If over-grouping persists after tuning, audit whether a Correlation Rule is also matching on the shared IP and creating a separate incident that then merges with grouped alerts.

### 2.4 Grouping Rule Precedence

| Priority | Grouping Axis | Notes |
|---|---|---|
| 1 | Causality chain (process lineage) | Strongest signal; same parent process tree always groups |
| 2 | Shared host + user | Same endpoint ID + username in short time window |
| 3 | Shared indicator (IP, domain, hash) | Where NAT grouping occurs — suppress with exclusion rules |
| 4 | Correlation rule match (XSIAM only) | Explicit YAML-defined conditions |
| 5 | Timeout / manual merge | Auto-close or analyst-driven |

### 2.5 Diagnostic Workflow

**Step 1: Identify the common artifact**

For each grouped alert, compare:
- Source IP, destination IP, NAT source/destination IP
- User, endpoint hostname, agent ID, device ID
- Process causality chain, file hash
- Detection rule name, MITRE technique
- Alert timestamp and data source

> **INTERPRETATION:** If the only common value is a NAT or gateway IP, the grouping is likely artifact-driven noise rather than a true incident relationship.

**Step 2: Query incident and alert data**

```xql
dataset = alerts
| filter alert_domain = "DOMAIN_SECURITY"
| filter incident_id = "<incident_id>"
| fields alert_id, alert_name, severity, source, actor_effective_username,
         agent_hostname, host_ip, action_local_ip, action_remote_ip, alert_timestamp
| sort asc alert_timestamp
```

> **NOTE:** Field names vary by tenant, license, data source, and schema version. Use schema autocomplete or inspect the alert record before operationalizing the query.

**Step 3: Document the grouping defect**

- Incident ID and alert IDs
- Shared artifact and whether it is weak or strong
- True source users and endpoints
- NAT, proxy, or VPN device involved
- Source data source and alert timestamps
- Whether grouping was driven by source IP, destination IP, or another entity
- Business impact: analyst time, SLA impact, escalation impact

### 2.6 Remediation and Design Guidance

| Control | Action |
|---|---|
| NAT awareness | Maintain a lookup table of NAT, proxy, VPN, and shared egress IPs |
| Analyst annotation | Add SOC notes identifying weak shared artifacts |
| Detection tuning | Avoid custom correlation rules that group solely on public egress IP |
| Query enrichment | Join alerts against known NAT, proxy, and gateway lookup datasets |
| Incident playbooks | Add early decision point: Is the shared artifact a many-to-one infrastructure component? |
| Escalation criteria | Require a stronger entity (user, hostname, hash, causality chain) before declaring a confirmed incident |

**Example shared infrastructure lookup (CSV format):**
```
ip_address, ip_type, owner, location, notes
203.0.113.10, nat_egress, Corporate Internet Edge, HQ, Shared user egress
203.0.113.20, vpn_egress, GlobalProtect Gateway, East, Remote user egress
198.51.100.50, proxy, Secure Web Gateway, Cloud, Shared proxy egress
```

---

## 3. Network Location Configuration

The XDR agent determines whether an endpoint is on an internal or external network at startup and after network changes. This determination drives which **Firewall Profile** the agent enforces. A miscategorized endpoint silently applies the wrong policy — often without any visible error.

### 3.1 How Network Location Detection Works

The agent runs two tests sequentially:

1. **LDAP connectivity test** — attempts to reach the configured domain controller(s) on port 389 (LDAP) or 636 (LDAPS). A successful bind indicates internal network.
2. **DNS resolution test** — resolves a configured internal hostname (e.g., `dc1.corp.example.com`) and validates the returned IP is in an expected internal range.

If **either** test passes → agent applies the **Internal Firewall Profile**  
If **both** fail → agent falls back to the **External Firewall Profile**

### 3.2 GlobalProtect Split-Tunnel Interaction

> **CRITICAL:** Split-tunnel GlobalProtect **invalidates both tests**. When GP is connected in split-tunnel mode, LDAP traffic reaches the DC and DNS queries resolve correctly — both via the VPN tunnel — from a laptop at a coffee shop. The agent concludes the endpoint is **internal** and enforces the Internal profile on an **untrusted network**. This is the most common profile misassignment scenario.

**In a typical split-tunnel configuration where 10.0.0.0/8 is tunneled and the DC is at 10.1.1.10:**

| Test | What Happens | Result |
|---|---|---|
| LDAP to 10.1.1.10:389 | Routes over GP tunnel; DC responds | **PASSES** |
| DNS query for dc1.corp.example.com | Forwards to internal DNS via tunnel | **PASSES** |
| Agent conclusion | Both tests pass | **INTERNAL** — Internal Firewall Profile applied |
| **Actual result** | Inbound rules more permissive than intended on an external/untrusted network | **SECURITY RISK** |

### 3.3 Misconfiguration Patterns

| Pattern | Result |
|---|---|
| Internal DNS suffix sent to remote endpoints | DNS test resolves internal record remotely |
| Domain controllers reachable through split tunnel | Domain controller test passes remotely |
| Internal-only FQDN reachable over GlobalProtect | Agent determines endpoint is internal |
| Same DNS record resolvable on LAN and VPN | No distinction between LAN and remote |
| Internal profile is less restrictive | Remote users receive LAN-style access rules |
| External profile is stricter | Remote users may unexpectedly lose access when tests fail |

### 3.4 Diagnostic Workflow

**Step 1: Confirm which profile is applied**

Collect from the Cortex console:
- Endpoint name and agent version
- Assigned policy and host firewall policy
- Current network location result
- Last network change time
- Current user and current IP addresses
- Current GlobalProtect status

**Step 2: Reproduce from a remote split-tunnel endpoint**

```powershell
ipconfig /all
route print
nslookup <internal_dns_name_used_by_cortex_network_location>
Test-NetConnection <domain_controller_fqdn> -Port 389
Test-NetConnection <domain_controller_fqdn> -Port 636
Test-NetConnection <domain_controller_fqdn> -Port 88
```

**Step 3: Test from three locations**

| Test | Corporate LAN | GP Remote (split-tunnel) | No VPN |
|---|---|---|---|
| Domain controller test | Pass | Should FAIL if GP = external | Fail |
| Internal DNS test | Pass | Should FAIL if GP = external | Fail |
| Host firewall profile | Internal | External / dedicated remote | External |

**Step 4: Verify active profile on endpoint**

```bash
cytool.exe runtime policy
cytool.exe policy show --module firewall

# Agent logs: C:\ProgramData\Cyvera\Logs\
# Search for 'NetworkLocation' entries showing test pass/fail and classification
```

### 3.5 Resolution Paths

#### Option A: Separate Profile per GP Connection State (Recommended)

1. In Cortex management (`Endpoints > Policy Management > Firewall`), clone your Internal profile and tighten inbound rules to match External posture.
2. Set targeting condition: **GlobalProtect Tunnel State = Connected AND Network Location = Internal**
3. Place this rule **above** the standard Internal profile so it takes precedence when the GP tunnel is active.
4. Validate on a test endpoint: force GP connection from off-net and check the active profile via `cytool.exe runtime policy`.

#### Option B: Non-Tunneled DC IP as LDAP Test Target

Configure a secondary LDAP test target using a DC IP on a network segment explicitly **excluded** from GP split-tunnel routes. If split-tunnel excludes `192.168.200.0/24`, place a probe host there and configure only that IP as the agent's LDAP test target.

> **WARNING — Operational risk:** If the probe host is unreachable, all remote endpoints fall back to External profile. Test thoroughly before production rollout.

#### Option C: Fixed Profile per Identity Scope

Disable automatic network-location switching and assign a fixed profile per agent policy scope using endpoint tags or AD group membership rather than network position.

| Approach | Accuracy | Complexity | GP Split-Tunnel Safe |
|---|---|---|---|
| Option A: GP state condition | High | Medium | **Yes** |
| Option B: Non-tunneled probe DC | High | Medium-High | **Yes** |
| Option C: Fixed profile by identity | Medium | Low | **Yes** |
| Default: LDAP+DNS with split-tunnel | Low | Lowest | **NO** |

---

## 4. Broker VM Syslog vs. Native Integrations

Palo Alto Networks provides two distinct ingestion paths for log sources. Choosing the wrong one, or misconfiguring either, results in data that is visible in the raw dataset but not normalized or correlated correctly.

### 4.1 Path Comparison

| Attribute | Broker VM (Syslog Receiver) | Native Integration |
|---|---|---|
| Transport | UDP/TCP/TLS syslog to Broker VM listener | API pull or push direct to Cortex cloud |
| Normalization | Parser applied at ingestion (may require custom parser) | Vendor-maintained parser, built-in normalization |
| XDM mapping | Manual or auto-parser; gaps common | Full XDM mapping maintained by PAN |
| Dataset landing | `xdr_raw_syslog` or named dataset if parser matches | `palo_alto_*` or vendor-specific `*_raw` |
| Alert generation | Only if XQL/correlation rule references the dataset | Automatic via built-in detection rules |
| Agent dependency | Broker VM required on-prem | None (cloud-to-cloud) or lightweight connector |

> **INFO — When to use Broker VM syslog:** Use it for sources with no native integration, sources that must stay on-prem (air-gapped), or sources requiring UDP syslog for legacy compatibility. For any source with a native Cortex integration (CrowdStrike, Okta, AWS CloudTrail, etc.), prefer the native path — it provides XDM normalization and built-in detection rules out of the box.

### 4.2 When to Use Each Method

| Requirement | Preferred Method |
|---|---|
| Palo Alto NGFW / Panorama logs, normal region and bandwidth | Native NGFW/Panorama integration |
| Firewalls in different region or with bandwidth constraints | Syslog Collector with CEF may be acceptable |
| Third-party firewall logs | Broker VM Syslog Collector or supported data source integration |
| Highest-quality Palo Alto content support | Native integration |
| Basic log retention/search only | Syslog can be sufficient |
| Detection, correlation, and normalized dashboards | Native integration is usually stronger |

### 4.3 Common Syslog Ingestion Issues

| Issue | Root Cause | Resolution |
|---|---|---|
| Data in `xdr_raw_syslog` but not expected dataset | Parser not matched or misconfigured | Validate parser assignment; use Parser Test with real sample log |
| Data present but no alerts fire | Built-in rules target normalized datasets | Fix parser mapping or write custom XQL correlation rule |
| Timestamp skew | Parser failed to extract original event timestamp | Use `timestamp_override` in parser to pull event time from log field |
| TLS syslog failing | Broker VM requires certificate chain to trusted CA | Add internal CA to Broker VM trusted store, or switch to TCP syslog |
| Sending raw PAN-OS syslog when CEF expected | Parser mismatch | Reconfigure log forwarding to match expected format |
| Wrong Vendor/Product values | Logs land in wrong raw dataset | Correct Vendor/Product in Syslog Collector configuration |
| UDP for high-value security logs | Packet loss risk under congestion | Switch to TCP or Secure TCP |

**Verify Broker VM Health:**

```bash
# From Broker VM CLI
broker status
broker syslog-collector status
broker syslog-collector stats --last 5m
```

### 4.4 Dataset Naming and Normalization

> **CRITICAL:** Do **not** assume every Palo Alto dataset is named `palo_alto_*`. Confirm actual dataset names in Dataset Management or XQL autocomplete before building operational queries.

Checklist:
- [ ] Confirm actual dataset names in Dataset Management or XQL autocomplete
- [ ] Confirm whether logs are present in the raw dataset
- [ ] Confirm whether logs are normalized into `xdr_data` or exposed through relevant presets
- [ ] Confirm whether expected content pack parsing rules, mappers, and data models are installed
- [ ] Build queries against **observed** dataset names, not assumed names

**Dataset discovery queries:**

```xql
dataset = panw_ngfw_raw | limit 10
dataset = alerts | filter alert_domain = "DOMAIN_SECURITY" | limit 50
```

---

## 5. Dataset Schema and XQL Field Reference

All Palo Alto Networks native data sources land in the `palo_alto_*` dataset family. Understanding which dataset holds which data is essential for accurate XQL queries and correlation rules.

### 5.1 palo_alto_* Dataset Reference

| Dataset | Content | Primary Use |
|---|---|---|
| `palo_alto_cortex_xdr` | XDR agent telemetry (process, file, network, registry events) | Threat hunting, process lineage, EDR correlation |
| `palo_alto_ngfw_traffic` | PAN-OS traffic logs from firewall or Panorama | Network flow analysis, policy audit |
| `palo_alto_ngfw_threat` | PAN-OS threat logs (IPS, AV, WildFire, DNS) | Network threat correlation |
| `palo_alto_prisma_cloud` | Prisma Cloud alerts and audit events | Cloud workload posture and runtime alerts |
| `palo_alto_cortex_xsoar` | XSOAR incident and playbook audit (XSIAM only) | SOC workflow auditing |
| `xdr_alerts` | Normalized alert records (all sources) | Alert investigation, grouping analysis |
| `xdr_data` | Raw agent telemetry pre-normalization | Deep hunt queries |
| `xdr_raw_syslog` | Unmatched syslog data from Broker VM | Troubleshooting ingestion issues |

### 5.2 XDM Field Mapping Pitfalls

1. **Field name mismatch across datasets:** `src_ip` in `xdr_alerts` maps to `xdm.network.client.ipv4` in normalized XDM — field names are not identical across datasets.

2. **Process image field confusion:** `actor_process_image_name` in `palo_alto_cortex_xdr` is the agent-reported executable; `action_process_image_name` is the spawned child. Mixing them produces false negatives in hunting queries.

3. **Ingestion time vs. event time:** `_time` is always **ingestion time**. Use `event_timestamp` for the original event time. Aggregations on `_time` will skew for high-latency sources (e.g., syslog over Broker VM).

### 5.3 Cross-Dataset Join Example

Correlate agent process events with NGFW threat logs to identify processes making suspicious outbound connections:

```xql
dataset = palo_alto_cortex_xdr
| fields endpoint_id, actor_process_image_name, action_remote_ip, event_timestamp
| filter action_remote_ip != null
| join type=inner (
    dataset = palo_alto_ngfw_threat
    | fields src_ip, dest_ip, threat_name, log_time
    | filter threat_name != null
  ) as fw on ($left.action_remote_ip = $right.dest_ip)
| fields endpoint_id, actor_process_image_name, action_remote_ip, fw.threat_name, event_timestamp
| sort desc event_timestamp
| limit 50
```

---

## 6. Cloud Identity Engine Activation

Cloud Identity Engine (CIE) synchronizes identity data (users, groups, devices) from directory sources (Active Directory, Azure AD, Okta) into the Palo Alto Networks hub for consumption by XDR, XSIAM, and NGFW policy. Activation and access are controlled through CSP, Activation Console, Common Services Identity & Access, Cortex Gateway, and CIE app roles.

### 6.1 Activation Requirements and Hub Role Mapping

CIE activation happens at **hub.paloaltonetworks.com**. The activating user must hold the **Superuser** role at the hub level — not just an XDR Instance Admin or Cortex Tenant Admin role.

> **CRITICAL:** A user who is an Administrator within a Cortex XDR instance does **not** automatically have hub-level Superuser rights. Attempting to activate CIE from that account will fail silently or return a generic permissions error. The activating account must be a **hub Superuser** with access to the specific tenant where the CIE instance will live.

| Role | Scope | Can Activate CIE |
|---|---|---|
| Hub Superuser | Entire hub tenant, all apps | **YES** |
| Hub App Admin | Specific app instance only | No |
| Cortex XDR Instance Admin | XDR instance only | No |
| Cortex XSIAM Admin | XSIAM instance only | No |
| Read-Only Analyst | View only, any scope | No |

> **INFO — MSP/Managed environments:** In managed tenants, the hub may be controlled by the managing party and customer Cortex admins may have no visibility into `hub.paloaltonetworks.com`. CIE activation requires coordination with the MSP's hub Superuser. Confirm whether the Cortex tenant is managed or customer-owned at the hub level before attempting self-service activation.

### 6.2 Common Failure States

| Failure | Likely Cause |
|---|---|
| User cannot access Activation Console | User has no assigned role |
| User can log in but cannot activate CIE | Missing account, app, or tenant permissions |
| CIE instance not visible in XSIAM | Wrong tenant or region |
| CIE activation exists but cannot pair to XSIAM | Incomplete CIE onboarding or wrong role |
| No one can assign roles | No available Account Admin or Superuser path |
| SSO user cannot perform CSP-only task | Task requires CSP-authenticated user path |

### 6.3 Remediation Workflow

1. Log in to `hub.paloaltonetworks.com` with the Palo Alto Networks account used to purchase or register the Cortex subscription. This account is the default Superuser.

2. Navigate to `Settings > User Management`. Identify whether any user has the Superuser role. If none do, escalate to your PAN account team or TAC.

3. Once a Superuser is confirmed, navigate to `Apps > Cloud Identity Engine > Activate`. Select the target tenant/account if multi-tenant.

4. After activation, connect the CIE instance to your directory via `CIE > Identity Providers > Add`. For Active Directory, deploy the **Cloud Identity Agent** on a domain-joined Windows server within the forest.

5. In Cortex XDR/XSIAM, navigate to `Settings > Identity > Cloud Identity Engine` and link the activated CIE instance to the Cortex tenant.

6. Confirm that Cloud Identity Engine and Cortex XSIAM are activated in the **same region**.

7. Assign required CIE app roles through **Common Services Identity & Access**.

8. Complete Cloud Identity Engine directory onboarding and validate directory data availability.

### 6.4 Post-Activation Validation

```xql
-- Validate user identity enrichment is flowing
dataset = xdr_alerts
| fields actor_primary_username, actor_primary_user_sid, alert_id
| filter actor_primary_username contains "@"
| comp count() by actor_primary_username
| sort desc count_
| limit 20
```

> **TIP:** If CIE is working, user records will be enriched with group membership visible in the Incident view under the **Identity** tab.

---

## 7. SOC Runbook

### 7.1 Unrelated Alerts Grouped into Same Incident

| Decision Point | Action |
|---|---|
| Are all alerts tied to the same endpoint ID? | If yes → keep grouped. If no → continue. |
| Are all alerts tied to the same user? | If yes → keep grouped unless user is a service account or shared identity. If no → continue. |
| Is the only common entity a public IP, proxy, VPN, or NAT address? | If yes → treat as likely false grouping. If no → continue. |
| Is there a common file hash, command line, destination, or process chain? | If yes → keep grouped and investigate. If no → split or annotate. |
| Is the shared entity in the known shared-infrastructure lookup? | If yes → downgrade grouping confidence. If no → escalate if entity is rare or suspicious. |

### 7.2 Analyst Note Template

Use this template when annotating grouped incidents for SOC documentation:

```
Incident grouping review completed.

Finding:
The alerts appear grouped due to shared artifact: <IP / hostname / user / hash>.

Assessment:
The shared artifact is a <NAT egress / VPN gateway / proxy / shared resolver / true endpoint>.
Based on available evidence, the alerts <do / do not> represent one related attack chain.

Affected alerts:
  - <alert_id_1>
  - <alert_id_2>

Action:
<Kept grouped / Split / Added NAT annotation / Escalated to detection engineering>
```

---

## 8. Engineering Runbook

### 8.1 Network Location Configuration Errors

Collect the following before troubleshooting:
- Endpoint hostname, agent version, assigned policy, applied host firewall profile
- Current user, network adapters, GlobalProtect status
- Route table while on VPN, DNS server list while on VPN
- DNS test result and domain controller reachability result
- Whether the user is on LAN, VPN, or off-network

| Condition | Expected (if LAN-only detection is correct) |
|---|---|
| On corporate LAN | DC test passes, DNS test passes, internal profile applies |
| On GlobalProtect split tunnel | DC and DNS tests should **FAIL** if GP should be external |
| Off VPN | DC and DNS tests fail, external profile applies |

### 8.2 Ingestion and Normalization Problems

Collect the following before troubleshooting:
- Data source name, integration type, dataset name
- Raw sample log, Vendor/Product values, timestamp format
- Parser/mapping status, content pack status
- Whether alerts are expected from vendor logic or Cortex analytics
- Whether data appears in raw datasets, `xdr_data`, presets, dashboards, and alert views

**Validation query examples:**

```xql
dataset = panw_ngfw_raw | limit 10
dataset = alerts | filter alert_domain = "DOMAIN_SECURITY" | limit 50
```

---

## 9. Preventive Design Standards

### 9.1 Alert Grouping Design Standard
- Maintain a known shared-infrastructure IP inventory
- Do not build custom incident correlation around NAT IP alone
- Treat NAT, proxy, VPN, and resolver IPs as weak entities
- Require at least one strong entity before declaring a unified incident
- Add SOC playbook logic for artifact quality assessment
- Periodically review top incident grouping artifacts for noise patterns

### 9.2 Network Location Design Standard
- Decide whether GlobalProtect remote users should be treated as internal, external, or remote-internal
- Do not allow internal/external classification to depend on a DNS name that resolves identically on LAN and VPN
- Do not use domain controller reachability as the only internal-location signal in split-tunnel environments
- Use dedicated endpoint policy allocation for remote users when possible
- Keep internal host firewall profiles least privilege
- Test every profile from LAN, VPN, and no-VPN states before production deployment

### 9.3 Ingestion Design Standard
- Prefer native Palo Alto NGFW / Panorama integrations when available
- Use Broker VM syslog for third-party sources or when native integration is not feasible
- Use Secure TCP where log integrity and source trust matter
- Explicitly configure Vendor/Product and Source Network on all Broker VM listeners
- Avoid broad any-source syslog listeners unless intentionally required
- Confirm parsing, normalization, dashboards, and detections before declaring onboarding complete
- Confirm actual dataset names instead of assuming `palo_alto_*`

### 9.4 Cloud Identity Engine Design Standard
- Activate Cloud Identity Engine in the **same region** as Cortex XSIAM
- Keep at least **two** named platform owners with appropriate hub administrative roles
- Document the CSP account, tenant, region, CIE instance, and XSIAM tenant relationship
- Avoid having only one person capable of assigning roles or managing activation
- Validate CIE directory sync before using CIE-backed policy or endpoint-management logic

---

## 10. Escalation Criteria

Escalate to TAC/engineering when:

- Case grouping repeatedly joins unrelated incidents and no local tuning or process control can reduce analyst burden
- Network Location Configuration produces inconsistent results across endpoints with the same route and DNS state
- The agent applies a host firewall profile that does not match the location test result shown in the console
- Native NGFW integration fails while required permissions and log forwarding are confirmed
- Broker VM metrics show logs received > logs sent, indicating a connectivity or processing issue
- Cloud Identity Engine cannot be activated because no user has the required tenant, Activation Console, Cortex Gateway, or CSP administrative path

---

## 11. Final Resolution Checklists

### 11.1 Alert Grouping
- [ ] Identified shared artifact
- [ ] Determined whether artifact is strong or weak
- [ ] Checked for NAT, proxy, VPN, or shared infrastructure
- [ ] Queried alerts and incident records
- [ ] Added SOC annotation or split incident if needed
- [ ] Updated known shared-infrastructure lookup
- [ ] Reviewed custom correlation rules for weak grouping logic

### 11.2 Network Location
- [ ] Confirmed applied host firewall profile
- [ ] Tested domain controller reachability from LAN, GlobalProtect, and no-VPN
- [ ] Tested DNS resolution from LAN, GlobalProtect, and no-VPN
- [ ] Confirmed whether split tunnel exposes internal tests
- [ ] Adjusted DNS test, GlobalProtect routing, or policy allocation
- [ ] Retested after network change
- [ ] Documented intended classification for LAN, VPN, and external users

### 11.3 Ingestion
- [ ] Confirmed ingestion method
- [ ] Confirmed raw logs arrive
- [ ] Confirmed actual dataset name
- [ ] Confirmed parsing and normalization
- [ ] Confirmed dashboards and content packs
- [ ] Confirmed detections trigger as expected
- [ ] Documented native versus Broker VM syslog design decision

### 11.4 Cloud Identity Engine
- [ ] Confirmed CSP account
- [ ] Confirmed tenant and region
- [ ] Confirmed CIE app role and hub Superuser path
- [ ] Completed CIE onboarding
- [ ] Paired CIE instance in Cortex XSIAM
- [ ] Validated identity data in policy/query workflows
- [ ] Documented at least two platform owners with admin access

---

## 12. Quick Reference Matrix

| Issue | Root Cause | Resolution |
|---|---|---|
| Unrelated alerts grouping into one incident | Shared NAT/proxy IP used as grouping indicator | Add NAT CIDRs to Network Exclusions; raise similarity threshold |
| Wrong firewall profile on remote endpoint | LDAP/DNS tests pass via GP split-tunnel | Add GP tunnel state condition to profile targeting (Option A) |
| Syslog data in `xdr_raw_syslog` only | Parser not matched or misconfigured on Broker VM | Validate parser assignment; use Parser Test with real sample |
| Syslog data present but no alerts fire | Built-in rules target normalized datasets, not raw syslog | Fix parser mapping or write custom XQL correlation rule |
| CIE activation fails with permissions error | Activating user lacks hub Superuser role | Activate from hub Superuser account; escalate to TAC if unavailable |
| XQL join returns no results across datasets | Field name mismatch; using raw vs. XDM fields | Use XDM field names; verify in Dataset Browser |
| Agent reports internal location off-prem | Split-tunnel routes LDAP/DNS to DC via tunnel | Use non-tunneled probe host or GP state-based profile condition |
| Dataset query returns no results | Assumed dataset name is wrong | Confirm actual dataset names in Dataset Management or XQL autocomplete |

---

*End of Article KB-CORTEX-XDR-001*
