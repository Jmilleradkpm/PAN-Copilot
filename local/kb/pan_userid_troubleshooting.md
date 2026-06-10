# KB: PAN-OS User-ID — Users Not Appearing in Traffic Logs

**Article ID:** KB-SEC-UID-001

| Field | Value |
|-------|-------|
| **Category** | Security Engineering |
| **Skill Level** | Intermediate – Advanced |
| **Applies To** | PAN-OS 9.x – 11.x \| Panorama \| GlobalProtect \| Windows AD Environments |
| **Primary Symptom** | Traffic logs show source IPs instead of usernames; Source User is blank, unknown, or inconsistent |
| **First Verification Command** | `show user ip-user-mapping all` |
| **Last Updated** | May 11, 2026 |

> **Core Principle:** A firewall can log a username only when a valid user-to-IP mapping exists for the source IP at the time the session is logged.

> **⚡ Critical First Check:** Before troubleshooting agents, domain controllers, LDAP, or GlobalProtect — confirm whether a mapping exists:
> ```
> show user ip-user-mapping all
> show user ip-user-mapping ip <client-ip>
> ```

---

## Contents

1. Issue Summary & First-Principles Explanation
2. Applies To
3. Common Symptoms
4. Initial Verification — Confirming Mappings Exist
5. Root Cause Analysis (Nine Categories)
   - 5.1 Mappings Do Not Exist
   - 5.2 Agent Cannot Read DC Security Logs
   - 5.3 WMI / WinRM Permissions Missing or Broken
   - 5.4 Required Windows Event IDs Missing
   - 5.5 Agent Monitoring Wrong Servers
   - 5.6 Include / Exclude Networks Misconfigured
   - 5.7 GlobalProtect-Only Users Not Mapped
   - 5.8 Group Mapping vs. User Mapping Confusion
   - 5.9 Agent vs. Agentless Design Mismatch
6. Structured Troubleshooting Workflow
7. Fix Matrix
8. Additional Considerations
9. CLI Quick Reference
10. Recommended Permanent Design
11. Escalation Data to Collect
12. Summary
13. References

---

## 1. Issue Summary & First-Principles Explanation

Traffic logs show only source IP addresses instead of usernames, or the Source User field is blank, unknown, or inconsistent. In Palo Alto Networks environments this almost always means the firewall did not have a valid user-to-IP mapping at the time the traffic log was generated.

### First-Principles

A firewall log cannot display a username by assumption. It can only display a username if the firewall connects three objective facts:

1. A packet or session arrives from a source IP address.
2. The firewall has a current mapping that says **this IP belongs to this username**.
3. The firewall uses that mapping when it writes the traffic log.

> **Core Troubleshooting Question:** Does the firewall have a valid user-to-IP mapping for the source IP at the time the traffic is logged?

If **no** — the log cannot reliably show the user. The firewall may still pass or block traffic based on IP, zone, application, or policy, but the username field cannot be populated without mapping data.

---

## 2. Applies To

- Palo Alto Networks Next-Generation Firewalls
- PAN-OS 9.x – 11.x
- PAN-OS User-ID (integrated and Windows-based agent)
- Active Directory / Windows domain environments
- WMI or WinRM server monitoring
- GlobalProtect-based User-ID mappings
- LDAP group mapping
- Panorama-managed deployments

---

## 3. Common Symptoms

| Symptom | Likely Meaning |
|---------|----------------|
| Source User field is blank | No valid IP-to-user mapping exists for the source IP |
| User appears for some users but not others | Mapping source incomplete — missing DCs, missing GP mapping, or subnet scope issue |
| User appears intermittently | Mapping aging, polling delay, DHCP reuse, VPN reconnect, stale or overwritten mapping |
| User appears in User-ID logs but not traffic logs | Zone User-ID enablement, timing, NAT, proxy, or session logging issue |
| Username appears but group-based rule does not match | User mapping works; LDAP group mapping, Base DN, or Group Include List is wrong |
| Remote users do not map | GlobalProtect gateway mapping, redistribution, or VPN pool inclusion incomplete |
| Only IPs appear after DC hardening | WMI, WinRM, Event Log Reader, DCOM, CIMV2, or firewall rules may have changed |

---

## 4. Initial Verification — Confirming Mappings Exist

Before touching any configuration, establish ground truth. Run the following from the firewall CLI (or Panorama in device context):

```
show user ip-user-mapping all
show user ip-user-mapping ip <IP>
show user ip-user-mapping all | match <domain>\<username>
show user user-ids
```

### Interpret the output

| Output Condition | What It Means / Where to Look Next |
|---|---|
| Table is empty | No mappings received at all — check agent connectivity, DC reachability, server monitor config |
| Partial entries — some IPs/users missing | Mapping source working but incomplete — check group membership, LDAP Base DN, GP gateway |
| Mappings exist but not in logs | Policy or log-forwarding issue, not User-ID — check security policy match, log profile, zone |
| Mappings are stale / wrong user on IP | IP reuse without cache clearing or timeout too low — tune cache expiry and DHCP lease duration |
| Mapping exists under unexpected domain format | Domain normalization or LDAP/group mapping mismatch |

### 4.2 Verify Mapping Source

After confirming whether a mapping exists, determine how the firewall learned (or failed to learn) it:

```
show log userid direction equal backward
show log userid datasourcetype equal globalprotect
show log userid datasourcetype equal kerberos
show log userid datasource equal agent
show log userid datasource equal event-log
show user user-id-agent state all          # agent connection state
show user server-monitor state all         # server monitor details
show user group-mapping state all          # LDAP group status
show user group name <group-DN>            # members in a mapped group
debug user-id log-ip-user-mapping yes      # enable verbose UID debug log
```

---

## 5. Root Cause Analysis

The sections below cover the nine most common root causes in order of frequency.

### 5.1 Mappings Do Not Exist — Missing or Misconfigured Source

The firewall needs at least one active mapping source. Common sources include Windows Security Event Logs from domain controllers, the Windows User-ID agent, the PAN-OS integrated agent, GlobalProtect, Authentication Portal, syslog, and XML API integrations.

| Mapping Source | What to Check |
|---|---|
| Windows User-ID Agent | Agent service running, monitored servers connected, firewall connected to agent, populated mapping table |
| Integrated User-ID Agent | Server monitor state, domain credentials, include/exclude networks, DC reachability |
| GlobalProtect | User authenticated through gateway, VPN pool included, mapping redistribution configured if needed |
| Syslog | Correct parser, source sending logs, expected event format, source IP extraction |
| XML API | External system submitting mappings correctly and with correct timeout behavior |
| Authentication Portal / Captive Portal | Authentication policy match, redirect path, certificate path, browser enforcement |

**Fix:**
1. Identify which system should provide the mapping
2. Confirm the source is producing authentication or logon data
3. Confirm the firewall or agent can ingest that data
4. Confirm the affected subnet is included in User-ID scope
5. Re-test with a fresh logon or VPN reconnect, then check the mapping table again

---

### 5.2 Windows User-ID Agent Cannot Read Domain Controller Security Logs

For AD-based mappings the User-ID process must read logon events from monitored servers. If the service account cannot read Security logs, the agent cannot extract mappings.

**Common causes:**
- Service account is not in Event Log Readers on the monitored server
- Service account password changed, expired, or the account is locked
- Domain controller firewall blocks WMI, WinRM, RPC, or remote event log access
- Server monitoring is using stale or incorrect credentials
- The agent is monitoring wrong or outdated domain controllers
- New DCs were added but not added to User-ID configuration
- Windows hardening or GPO changes broke remote event log access

**Verification:**

```
show user user-id-agent state all
show user user-id-agent config name <agent-name>
show log userid datasourcename equal <agent-name> direction equal backward
```

**Fix:**
- Use a dedicated AD service account for User-ID
- Add the account to **Event Log Readers** on monitored DCs or event collectors
- Confirm the account can read the Security log remotely
- Confirm the account is not locked, expired, or denied by GPO
- Restart the User-ID agent service after credential changes
- Generate a fresh user logon event and verify a new mapping appears

---

### 5.3 WMI / WinRM Permissions Missing or Broken

The most common cause of zero or intermittent mappings in agentless deployments is insufficient WMI or WinRM permissions on the Domain Controllers being monitored.

> **Why this happens:** The PAN-OS User-ID process connects to each DC's WMI namespace (`root\cimv2`) or WinRM endpoint as the configured service account. If that account lacks the necessary rights, the connection succeeds at the TCP layer but the event log query fails silently.

#### Required Permissions — WMI (Agentless)

The service account must be granted all of the following on each monitored DC:
- **Remote Launch** — Component Services → DCOM Config → Windows Management Instrumentation
- **Remote Activation** — same DCOM object
- **Enable Account / Remote Enable** — WMI namespace `root\cimv2` security
- **Event Log Readers** — built-in local group on each DC
- **Distributed COM Users** — built-in local group on each DC

#### Required Permissions — WinRM (Agentless, PAN-OS 10.1+)

- WinRM service must be running and configured (`winrm quickconfig`)
- Service account must be in the **Remote Management Users** local group on each DC
- WinRM HTTPS listener recommended in production; confirm certificate trust from firewall

#### WMI Checklist

| Check | Detail |
|---|---|
| Distributed COM Users | Service account must be a member on each DC |
| WMI namespace root\CIMV2 | Enable Account and Remote Enable permissions required |
| Windows Firewall | Inbound WMI and RPC/DCOM rules must permit the firewall MGT IP |
| UAC remote restrictions | May block non-admin accounts from remote WMI; test explicitly |
| GPO hardening | Audit for GPO that changes remote management rights after hardening events |

#### WinRM Checklist

```
winrm enumerate winrm/config/listener
Test-WSMan <domain-controller>
```

- WinRM service is running
- TCP 5985 (HTTP) or 5986 (HTTPS) is reachable
- HTTPS listener and certificate are valid if using WinRM over HTTPS
- Service account can read event logs
- Time synchronization is correct between firewall, agent, and DCs

#### Verification from Windows

```powershell
# Test WMI access with the service account:
wmic /node:<DC-IP> /user:<domain\svcaccount> computersystem get name

# Test WinRM connectivity:
Test-WSMan -ComputerName <DC-IP> -Credential (Get-Credential)
```

> **Tip:** On the firewall, go to **Monitor → Logs → System** and filter on `subtype eq userid` to see connection errors and authentication failures from the User-ID process in real time.

#### Network requirements (firewall MGT → DC)

| Protocol / Port | Purpose |
|---|---|
| TCP 135 | WMI endpoint mapper (DCOM) |
| TCP 49152–65535 | Dynamic RPC ports used after endpoint mapper |
| TCP 5985 | WinRM (HTTP) |
| TCP 5986 | WinRM (HTTPS) — preferred in production |
| TCP 5007 | User-ID agent to firewall (agent deployments) |

**Fix:**
- Prefer WinRM over legacy WMI where possible
- Validate Event Log Reader access first
- For WMI: validate DCOM and CIMV2 permissions
- For WinRM: validate listener, firewall, authentication, and event log access

---

### 5.4 Required Windows Event IDs Missing

Even with correct permissions, the firewall will miss mappings if it is not monitoring the right Windows Security event log IDs.

| Event ID | Auth Type / Notes |
|---|---|
| **4624** | Interactive / Network Logon (NTLM, local). Logon Types 2, 3, 10 are useful; Type 5 (service) generates noise |
| **4768** | Kerberos TGT request — fired at initial domain authentication. Most useful for session start mapping |
| **4769** | Kerberos service ticket request — fired frequently during active sessions; high volume on busy DCs |
| **4770** | Kerberos ticket renewal — useful in long-session environments (traders, kiosks) |
| **4648** | Explicit credentials logon — useful when users run apps as a different account; can cause incorrect mappings if not filtered |

> **⚠ Common Mistake:** Environments that use Kerberos exclusively (domain-joined Windows 10/11 with modern authentication) will generate few or no 4624 events at the DC. If only 4624 is enabled in server monitoring, you will see near-zero mappings. **Enable 4768 and 4769 in these environments.**

#### Audit Policy Must Be Enabled on DCs

The events only appear in the Security log if the corresponding audit policy is active. Verify via Group Policy or `auditpol`:

```
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"Kerberos Authentication Service"
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

All relevant subcategories should show **Success** or **Success and Failure**. If they show **No Auditing**, User-ID will have no events to consume regardless of all other configuration.

**Verification:**

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624,4768,4769,4770
} -MaxEvents 50
```

**Fix:**
1. Verify DC audit policy includes logon and Kerberos events
2. Verify Windows Event Forwarding subscriptions include the needed event IDs
3. Confirm the User-ID agent monitors the event collector or the correct DCs
4. Reproduce with a fresh user logon and check whether the mapping appears

---

### 5.5 Agent Monitoring Wrong or Incomplete Set of Servers

In large AD environments, users may authenticate against different domain controllers. If the User-ID agent monitors only some DCs, users authenticating through unmonitored DCs will not be mapped.

**Verification:**

```
show user user-id-agent config name <agent-name>

# Compare against actual DC list:
nltest /dclist:<domain>
```

**Fix:**
- Add missing domain controllers
- Add Windows Event Collectors if using Windows Event Forwarding
- Add Exchange servers if users authenticate there and Exchange events are part of the design
- Re-run auto-discovery if applicable — but do not assume it captures every needed source
- Document ownership so new DCs are added to User-ID monitoring during AD changes

---

### 5.6 Include / Exclude Networks Misconfigured

User-ID can be scoped to specific networks. If the client subnet is excluded or include networks are too narrow, mappings will not be created for affected users.

**Verification:**

```
show user server-monitor state all
show user ip-user-mapping ip <client-ip>
show user include-exclude-networks
```

| Configuration Issue | Result |
|---|---|
| Include only 10.1.0.0/16 but users are in 10.2.0.0/16 | Users in 10.2.0.0/16 do not map |
| Exclude subnet overlaps user VLAN | Users in that VLAN are ignored |
| Exclude configured without a matching include design | Mapping behavior may exclude more users than intended |
| VPN pool not included | Remote users do not appear in logs |

**Fix:**
- Add all wired user VLANs
- Add corporate wireless user subnets
- Add VPN address pools
- Add VDI and remote access pools where applicable
- Avoid including guest, DMZ, server-only, NAT pool, or infrastructure-only subnets unless required
- Commit and test with a fresh logon or VPN reconnect

Navigate to: **Device → User Identification → User Mapping → Exclude Networks**

---

### 5.7 GlobalProtect-Only Users Not Being Mapped

Users connecting exclusively via GlobalProtect — particularly remote workers who never authenticate directly against a monitored DC — will not generate security log events visible to the server monitor. Their authentication occurs at the GP gateway, not at a DC.

**Typical Failure Modes:**
- GlobalProtect portal exists, but the gateway is not creating or sharing the mapping
- The firewall enforcing policy is not the same firewall receiving the GP mapping
- User-ID redistribution is missing between firewalls
- The VPN pool is excluded from User-ID include networks
- Authentication override or SSO behavior prevents expected mapping refresh

#### The Fix — Enable User-ID on the GlobalProtect Gateway

Navigate to: **Network → GlobalProtect → Gateways → [Gateway] → Agent → Client Settings → Network Settings**

- Generate HIP reports — required for GP-sourced user mapping
- User-ID: enabled on the gateway zone (the zone GP tunnel interfaces land in)
- Include the GP gateway IP in the Network Access → User-ID Agent → Redistribution list if using a hub-and-spoke Panorama architecture

**Verification:**

```
show log userid datasourcetype equal globalprotect
show user ip-user-mapping all type GP
show user ip-user-mapping all | match <vpn-pool-subnet>
show user ip-user-mapping ip <vpn-client-ip>
```

> **Architecture Note:** In split-tunnel GP deployments, the gateway only sees tunnel-destined traffic. Ensure User-ID redistribution is configured if multiple firewalls need to consume the same GP user mappings. Use **Device → User Identification → User-ID Agent** to configure redistribution between devices.

---

### 5.8 Group Mapping vs. User Mapping Confusion

User mapping and group mapping are **separate processes**. User mapping answers which username owns an IP address. Group mapping answers which groups that username belongs to. A user can appear in traffic logs and still fail to match a group-based policy if LDAP group mapping is wrong.

| Symptom | Meaning |
|---|---|
| Username appears in logs | IP-to-user mapping works correctly |
| Group-based policy does not match | LDAP group mapping issue — troubleshoot separately |
| User appears as domain\user, policy expects different format | Domain normalization issue may exist |
| Some groups work but others do not | LDAP Base DN, group include list, nested groups, or multi-domain search issue |
| Group shows 0 members despite users being in AD | Base DN scoped too narrowly — users are in an OU outside the search root |
| Group mapping stopped after AD restructuring | User accounts moved to a new OU outside the Base DN |

#### LDAP Base DN

The Base DN determines where the firewall starts searching for users and groups. If it is too narrow, the firewall may not see users or groups outside that subtree.

```
# Recommended — use domain root to ensure full coverage:
DC=corp,DC=example,DC=com

# Potentially too narrow — only covers one branch:
OU=Users,DC=corp,DC=example,DC=com
```

> **⚠ Important — LDAP Group Filter:** Under **Device → User Identification → Group Mapping Settings**, the **Group Include List** restricts which groups are pulled into the firewall's local cache. If a group your policy references is not on this list, it will never resolve — even if the LDAP query returns it. Always verify the include list when adding new policy groups.

**Verification:**

```
show user group-mapping state all
show user group-mapping statistics
show user group list
show user group name "<group-name>"

# Force immediate LDAP group refresh:
debug user-id refresh-group-mapping all
```

**Fix:**
- Set the Base DN high enough to include all relevant users and groups
- Use Global Catalog when users and groups span multiple domains
- Verify LDAP bind account permissions
- Confirm the group include list is not excluding required groups
- Confirm nested group behavior if the policy depends on nested membership (default nesting limit: 10 levels)
- Normalize domain format across User-ID and group mapping

---

### 5.9 Agent vs. Agentless Design Mismatch

Most User-ID problems manifest differently depending on which mode is deployed. Identifying the mode is essential during troubleshooting.

| Attribute | Windows-Based Agent (UIA) | Agentless (PAN-OS Direct WMI) |
|---|---|---|
| Deployment | Agent service installed on a Windows host (domain member) | Firewall connects directly to DCs via WMI/WinRM |
| Scale | Recommended for large environments; agent can monitor multiple DCs | Suitable for small/medium; CPU overhead on firewall increases with DC count |
| Failure mode | Agent-to-firewall TCP 5007 link; single point of failure if agent host goes down | Per-DC connection failure; partial outage if one DC unreachable |
| Auth requirement | Service account on agent host + DC WMI rights | Service account with WMI/WinRM rights direct from firewall MGT IP |
| Syslog/XML API | Yes — can receive external identity sources | Limited to WMI/WinRM polling |
| Troubleshooting | Check agent service, agent logs, TCP 5007 to firewall | Check firewall system logs (subtype userid), WMI access from MGT |

#### Agent Deployment — Key Checks

- TCP 5007 must be open between agent host and firewall MGT or data-plane interface
- Agent service account requires local admin on the agent host and Event Log Readers on DCs

```
# Firewall CLI:
show user user-id-agent state all

# Agent log (on the Windows agent host):
%ProgramFiles%\Palo Alto Networks\User-ID Agent\UaDebug.log
```

#### Agentless Deployment — Key Checks

- Firewall MGT interface must reach DC on TCP 135 and dynamic RPC ports (49152–65535)
- Windows Firewall on DCs must permit inbound WMI from the firewall MGT IP

```
show user server-monitor state all
show user server-monitor statistics

# System log filter:
subtype eq userid
```

#### Practical Design Recommendation

| Environment | Recommended Direction |
|---|---|
| Small single-domain AD | Integrated User-ID agent can be acceptable |
| Large AD with many DCs | Windows User-ID Agent or Windows Event Collector model is usually cleaner |
| Heavy remote workforce | GlobalProtect mappings should be primary |
| Multi-firewall environment | Use User-ID redistribution deliberately; validate the enforcing firewall has the mapping |
| Mixed OS, wireless, NAC, or VPN | Prefer syslog, XML API, NAC integrations, and GlobalProtect where appropriate |
| High-security environment | Avoid legacy client probing unless explicitly required and approved |

---

## 6. Structured Troubleshooting Workflow

Use this workflow when a ticket arrives stating "users not in logs." Work top to bottom; stop when you find the failing layer.

### Step 1 — Pick One Affected User and One Affected IP

Collect: Username, Client IP, Source Zone, Timestamp, Firewall serial/hostname, Expected AD group, Connection type (LAN / VPN / wireless / VDI / RDS).

### Step 2 — Check Whether the Mapping Exists

```
show user ip-user-mapping ip <client-ip>
```

| Result | Next Step |
|---|---|
| No mapping exists | Troubleshoot mapping acquisition (Sections 5.1–5.7) |
| Mapping exists | Check: correct user, correct domain format, correct source, present on enforcing firewall, present before session was logged |
| Mapping exists but shows wrong user | Investigate stale mapping, shared endpoint, DHCP reuse, proxy, NAT, terminal server |

### Step 3 — Check User-ID Agent or Server Monitor Health

```
show user user-id-agent state all
show user user-id-agent config name <agent-name>
show user server-monitor state all
show user server-monitor statistics
```

All agents/DCs should show **Connected**. If not: check network, credentials, service state.

### Step 4 — Confirm Security Events Exist on DC

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624,4768,4769,4770
} -MaxEvents 100
```

> **⚠ Important:** If Windows events do not exist, this is not yet a firewall problem. Fix AD auditing, event generation, or event forwarding first.

### Step 5 — Confirm Permissions

- Service account exists in each monitored domain, is not locked out, password is current
- Event Log Reader access exists on each DC
- DCOM permissions exist if WMI is used
- CIMV2 permissions exist if WMI probing is used
- WinRM access exists if WinRM is used
- Account is not blocked by GPO deny rules

### Step 6 — Confirm Subnet Scope

- **Include:** user VLANs, corporate wireless, VPN pools, VDI pools, remote access networks
- **Exclude:** guest, DMZ, server-only, NAT pool, proxy, and infrastructure-only networks

### Step 7 — Check GlobalProtect Mapping

```
show log userid datasourcetype equal globalprotect
show user ip-user-mapping all type GP
show user ip-user-mapping ip <vpn-client-ip>
```

If the GP gateway has the mapping but another firewall does not, check User-ID redistribution.

### Step 8 — Check Group Mapping Separately

```
show user group-mapping state all
show user group-mapping statistics
show user group name "<group-name>"
```

If the username appears in logs but the policy does not match the expected AD group, troubleshoot LDAP group mapping rather than IP-to-user mapping.

### Step 9 — Check Security Policy Log

Verify the policy hit shows the username column populated. If blank but a mapping exists: check log forwarding, zone mismatch, or whether the mapping existed when the session was created.

---

## 7. Fix Matrix

| Problem Found | Corrective Action |
|---|---|
| No IP-user mapping | Fix mapping source: User-ID agent, GlobalProtect, syslog, XML API, or Authentication Portal |
| User-ID agent disconnected | Restore agent service, firewall-agent connectivity, port, and certificate if applicable |
| Domain controller disconnected | Fix WMI, WinRM, RPC, firewall, DNS, or credentials |
| Missing event IDs | Fix audit policy or Windows Event Forwarding subscription |
| Service account lacks permissions | Add Event Log Reader, DCOM, CIMV2, or WinRM permissions as required |
| VPN users missing | Validate GlobalProtect gateway mappings and VPN pool include networks |
| User appears but group policy fails | Fix LDAP Base DN, group include list, nested groups, or domain format |
| Wrong username mapped | Clear stale mapping; investigate DHCP reuse, proxy, NAT, terminal services, or shared endpoints |
| Only some subnets affected | Fix User-ID include/exclude network scope |
| Only some DC-authenticated users affected | Add missing domain controllers or event collectors |
| Logs blank but mapping exists now | Check whether mapping existed when the session was created or logged |

---

## 8. Additional Considerations

### 8.1 User-ID Timeout and IP Reuse

The default IP-user mapping timeout is **45 minutes**. In DHCP environments with short lease times, users may appear under a stale IP-to-user mapping after IP reassignment.

Navigate to: **Device → User Identification → User Mapping → User-ID Agent Setup → User Mapping Cache Expiry**

Match cache expiry to your DHCP lease duration. Also consider enabling syslog-based IP reclaim if your DHCP server can forward lease events.

### 8.2 Excluded Subnets

**Device → User Identification → User Mapping → Exclude Networks** allows suppression of User-ID for specific subnets (servers, printers, IoT, etc.). Verify that users' subnets are not inadvertently listed here.

```
show user include-exclude-networks
```

### 8.3 Captive Portal Fallback

When agentless/agent methods fail, Captive Portal can serve as a fallback identification mechanism for HTTP/HTTPS traffic. If users are partially mapped but some still show as unknown, verify Captive Portal is configured on the zone and that the authentication profile is functional.

> **Note:** Captive Portal will not help for non-browser traffic (RDP, thick clients, etc.).

### 8.4 Redistribution to Downstream Firewalls

In hub-and-spoke or data-center architectures, a single "collector" firewall or Panorama instance may learn all mappings and redistribute them to spoke firewalls. If spoke firewalls show empty mapping tables while the hub is populated, check:

- Redistribution agent configured on spoke pointing to hub
- TCP 5007 open between spoke and hub
- Hub configured to allow redistribution: **Device → User Identification → User-ID Agent → enabled**

---

## 9. CLI Quick Reference

### 9.1 Mapping Commands

```
show user ip-user-mapping all
show user ip-user-mapping ip <ip-address>
show user ip-user-mapping all | match <domain>\<username>
show user user-ids
```

### 9.2 Agent and Server Monitor Commands

```
show user user-id-agent state all
show user user-id-agent config name <agent-name>
show user server-monitor state all
show user server-monitor statistics
```

### 9.3 User-ID Log Commands

```
show log userid direction equal backward
show log userid datasourcename equal <agent-name> direction equal backward
show log userid datasourcetype equal globalprotect
show log userid datasourcetype equal kerberos
show log userid datasource equal agent
show log userid datasource equal event-log
```

### 9.4 Group Mapping Commands

```
show user group-mapping state all
show user group-mapping statistics
show user group list
show user group name "<group-name>"
```

### 9.5 Debug Commands

```
debug user-id log-ip-user-mapping yes     # Enable verbose mapping debug log
debug user-id log-ip-user-mapping no      # Disable after troubleshooting
debug user-id refresh-group-mapping all   # Force immediate LDAP group refresh
less mp-log useridd.log                   # User-ID daemon log (management plane)
```

### 9.6 Clear Cache Commands

> **⚠ Caution:** Use carefully — clearing the User-ID cache can temporarily affect user-based policy decisions. Use narrowly when possible.

```
clear user-cache ip <ip-address/netmask>
clear user-cache all
```

### 9.7 Full Command Cheat Sheet

| Command | Purpose |
|---|---|
| `show user ip-user-mapping all` | Full IP-to-user mapping table |
| `show user ip-user-mapping ip <IP>` | Single IP lookup |
| `show user user-id-agent state all` | Agent connection state |
| `show user server-monitor state all` | Agentless DC monitor state |
| `show user server-monitor statistics` | Poll counts, errors per DC |
| `show user group-mapping state all` | LDAP group mapping health |
| `show user group name <group-DN>` | Members resolved for a specific group |
| `show user include-exclude-networks` | Subnets excluded from User-ID |
| `debug user-id log-ip-user-mapping yes` | Enable per-mapping debug logging |
| `debug user-id refresh-group-mapping all` | Force immediate LDAP group refresh |
| `less mp-log useridd.log` | User-ID daemon log (management plane) |

---

## 10. Recommended Permanent Design

### 10.1 Best-Practice Mapping Strategy by User Type

| User Type | Preferred Mapping Source |
|---|---|
| VPN users | GlobalProtect |
| Internal domain users | Domain controller event logs through User-ID agent or integrated agent |
| Wireless users | Wireless controller syslog or NAC integration |
| Non-Windows devices | Syslog, XML API, NAC, or Authentication Portal |
| High-value applications | Authentication Portal as confirmation |
| VDI, RDS, or Citrix users | Terminal Server Agent or a supported equivalent design |

### 10.2 Operational Controls

- Monitor User-ID agent health and server monitor state continuously
- Alert on User-ID agent disconnection
- Document every domain controller and event collector used for mappings
- Include User-ID validation in firewall upgrade and DC hardening change plans
- Review include/exclude networks after new VLANs, VPN pools, or wireless networks are added
- Validate GlobalProtect mapping and redistribution after topology changes
- Keep service account credentials least-privilege and documented

---

## 11. Escalation Data to Collect

### 11.1 Firewall Data

```
show system info
show user ip-user-mapping ip <client-ip>
show user user-id-agent state all
show user server-monitor state all
show user server-monitor statistics
show user group-mapping state all
show log userid direction equal backward
```

### 11.2 User Details

- Username
- Client IP
- Source zone
- AD domain
- Expected AD group
- Connection type: LAN, VPN, wireless, VDI, or RDS
- Timestamp of failed log entry
- Firewall that processed the session
- Screenshot or export of the affected traffic log

### 11.3 Windows and AD Data

- Domain controller that authenticated the user
- Security events 4624, 4768, 4769, and 4770 from the DC
- User-ID service account permissions (Event Log Readers, DCOM, WinRM)
- WMI or WinRM test result
- Windows Event Forwarding subscription if used

---

## 12. Summary

When users do not appear in Palo Alto Networks logs, start with the most basic fact: the firewall can only log a username if it has a valid IP-to-user mapping.

```
show user ip-user-mapping all
```

Then isolate the issue into one of three categories:

1. **No mapping exists.** Troubleshoot User-ID collection: DC logs, WMI or WinRM, GlobalProtect, syslog, XML API, or Authentication Portal.

2. **Mapping exists but logs still do not show the user.** Check timing, source zone, include/exclude networks, NAT or proxy behavior, and which firewall processed the traffic.

3. **User appears but policy or group matching fails.** Troubleshoot LDAP group mapping, Base DN scope, group include lists, nested groups, and domain format.

> **Bottom Line:** Most User-ID visibility issues come down to one missing link in the chain — authentication event → mapping source → firewall mapping table → traffic log.

---

## 13. References

- CLI Cheat Sheet: User-ID
- Configure the Windows-Based User-ID Agent for User Mapping
- Create a Dedicated Service Account for the User-ID Agent
- Configure Server Monitoring Using WinRM
- Configure Windows Log Forwarding
- Configure User Mapping Using the PAN-OS Integrated User-ID Agent
- User-ID Best Practices for GlobalProtect
- Map Users to Groups
- Map IP Addresses to Usernames Using Authentication Portal

---

*End of Article KB-SEC-UID-001*
