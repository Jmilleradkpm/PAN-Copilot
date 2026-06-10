# KB: Panorama Commit/Push Failures, Template Stacks, Device Groups, Offline Upgrades, SAML Roles, and Log Collector Design

**Article ID:** KB-PAN-MGMT-001

| Field | Value |
|-------|-------|
| **Applies To** | Palo Alto Networks Panorama 10.2 – 11.1.x, M-Series & VM, Dedicated & Mixed-Mode Log Collectors |
| **Category** | Architecture / Operations — Design & Troubleshooting |
| **Audience** | Firewall engineers, Panorama administrators, SOC platform owners, network security architects, escalation engineers |
| **Primary Use** | Troubleshooting failed commits, failed pushes, object conflicts, admin role authorization, offline update workflows, logging architecture decisions |
| **Last Updated** | May 2026 |

> **Operational Principle:** Treat Panorama as a hierarchy-driven configuration compiler. A stable deployment requires clear ownership of settings, objects, roles, and logging responsibilities.

> **Core Rule:** Panorama must commit its own candidate configuration before it can push that configuration to managed devices. A push failure means the rendered configuration could not be accepted by one or more targets — not that Panorama itself failed.

---

## Contents

1. Foundational Model — Two-Stage Commit/Push Architecture
2. Common Symptoms
3. Commit vs. Push Mental Model
4. High-Probability Root Causes
   - 4.1 Template-Stack Precedence Conflict
   - 4.2 Cross-Template Reference Assumptions
   - 4.3 Device-Group Hierarchy Misunderstanding
   - 4.4 Shared vs. Local Object Name Collisions
   - 4.5 Panorama Push Blocked by Firewall Settings
   - 4.6 Local Firewall Changes Causing Push Failures
   - 4.7 Multi-VSYS and Shared Object Push Failures
5. Commit and Push Failure Modes (Deep Dive)
   - 5.1 Partial Push Failures
   - 5.2 Object Dependency Errors
   - 5.3 Template vs. Device-Group Commit Scope Confusion
   - 5.4 High-Availability Push Sequencing
   - 5.5 Commit Locks and Configuration Locks
6. Template Stack Precedence and Variables
   - 6.1 Stack Resolution Order
   - 6.2 Template Variables
   - 6.3 Template Stack Design Patterns
7. Device Group Hierarchy and Object Inheritance
   - 7.1 Hierarchy Structure
   - 7.2 Policy Inheritance and Evaluation Order
   - 7.3 Shared vs. Device-Group Objects
8. Offline / Air-Gapped PAN-OS Upgrades
   - 8.1 What Requires Internet Access by Default
   - 8.2 Offline Upgrade Workflow
   - 8.3 Panorama Software Offline Upgrade
   - 8.4 Proxy Configuration for Semi-Restricted Environments
9. SAML-Based Admin Role Assignment (11.1.x)
   - 9.1 SAML Authentication Flow
   - 9.2 Two Role-Assignment Models
   - 9.3 Configuration Reference — Entra ID as IdP
   - 9.4 Troubleshooting SAML Role Assignment Failures
   - 9.5 Certificate Validation (11.1.x)
10. Log Collector Design — Dedicated vs. Mixed Mode
    - 10.1 Log Collector Modes
    - 10.2 Collector Groups
    - 10.3 Sizing Methodology
    - 10.4 Operational Considerations
11. Troubleshooting Workflow
12. Fast Decision Tree
13. Preventive Checklists
14. Escalation Data to Collect
15. References

---

## 1. Foundational Model — Two-Stage Commit/Push Architecture

Panorama does not push one flat configuration. It renders a device-specific result from multiple inherited and local configuration sources. Understanding this is foundational — conflating commit and push is the single most common source of operational confusion and failed change windows.

**Panorama renders configuration from:**
- Shared, device groups, templates, template stacks
- Local device state, admin role permissions
- Plugin state, content versions
- Target-device capabilities

### The Two-Stage Model

| Operation | What Actually Happens |
|---|---|
| **Panorama Commit** | Validates and saves config to Panorama's candidate → running. **No firewall is touched.** |
| **Push to Devices** | Sends merged config (template + device-group) to each selected firewall. Firewall performs a local commit. |
| **Commit-and-Push** | Atomic shortcut: commits Panorama first, then pushes. Still two discrete phases under the hood. |
| **Device-Local Commit** | Commit run on the firewall itself (e.g., via SSH). Applies only locally-managed config; does **NOT** pull Panorama updates. |

**Practical troubleshooting rule:** Always split the problem into two questions:
1. Can Panorama commit the configuration to itself?
2. Can the target firewall or collector accept the pushed result?

Do not troubleshoot both at the same time.

---

## 2. Common Symptoms

| Symptom Category | Examples | Likely Failure Domain |
|---|---|---|
| **Panorama commit** | Commit fails, validation passes but commit fails, job pending, commit fails for one admin only | Candidate configuration, commit locks, Panorama health, storage, permissions, plugin state, invalid references |
| **Push to device** | Device group push fails, template stack push fails, one HA peer accepts push but other does not, firewall stays out-of-sync | Target rendering, local firewall config, duplicate objects, connectivity, version/content mismatch |
| **Design** | Too many objects in Shared, unclear inheritance, undocumented stack order, site-specific values placed globally | Panorama hierarchy and ownership model |
| **Admin authorization** | SAML login succeeds but commit/push fails, custom role cannot select push scope, admin can commit but not push | SAML attributes, access domains, custom admin roles, Push All Changes, Push For Other Admins |
| **Logging** | High log loss, poor query performance, short retention, collector group instability, Panorama responsiveness issues | Collector mode, disk sizing, redundancy, collector count, management/logging resource contention |

---

## 3. Commit vs. Push Mental Model

| Operation | What It Does | Failure Meaning |
|---|---|---|
| **Validate** | Checks pending configuration for structural and reference errors | The candidate configuration has syntax, reference, or validation problems |
| **Commit to Panorama** | Saves Panorama candidate configuration into Panorama running configuration | Panorama itself cannot accept the candidate configuration |
| **Push to Devices** | Sends Panorama running configuration to firewalls, Log Collectors, or managed systems | The target cannot accept, receive, or apply the rendered configuration |
| **Commit and Push** | Commits to Panorama and then pushes to selected targets | Either the Panorama commit or the target push can fail; isolate which failed first |

---

## 4. High-Probability Root Causes

### 4.1 Template-Stack Precedence Conflict

A template stack combines multiple templates. Where overlapping settings exist, the **higher template** in the stack takes precedence over lower templates.

**Example template stack order:**
```
1. Branch-Specific-Template      ← highest precedence
2. Regional-Template
3. Global-Base-Template          ← lowest precedence
```

If Branch-Specific-Template and Global-Base-Template both define the same DNS server, NTP server, interface parameter, or management profile — the higher template wins.

| Failure Pattern | Why It Happens | Fix |
|---|---|---|
| Interface defined differently in two templates | A global and site template both configure the same interface with different modes | Move interface ownership to one layer or document intentional override |
| Device value correct in one template but wrong on firewall | A higher template silently overrides the lower template | Review template stack order before push; preview rendered changes |
| Push succeeds but site behavior is wrong | The rendered configuration is valid, but not the value the engineer expected | Use naming, documentation, and per-firewall variables to remove ambiguity |

> **Resolution is element-level, not object-level.** If Template A defines interface eth1/1 and Template B also defines eth1/1, Template A's definition wins — Template B's eth1/1 is completely ignored, not merged.

### 4.2 Cross-Template Reference Assumptions

Do not assume a setting in one template can safely reference an object configured in another template merely because both templates are in the same stack. **Closely coupled objects should live in the same template.**

**Example:** If one template defines a zone and another template defines a zone protection profile, referencing across those templates can create unresolved reference behavior during commit or push.

### 4.3 Device-Group Hierarchy Misunderstanding

Device groups manage **policy and objects**. Templates and template stacks manage **network and device configuration**. Confusing these two configuration planes causes many Panorama problems.

**Typical device-group hierarchy:**
```
Shared
└── Global
    └── Region
        └── Site
            └── Firewall / HA Pair
```

| Hierarchy Layer | Recommended Use | Design Risk |
|---|---|---|
| **Shared** | Only universal objects and policies that apply broadly across the estate | Shared becomes a dumping ground; site-specific objects get inherited everywhere |
| **Parent DG** | Common policy and reusable objects for a business unit, region, or platform | Parent rules unexpectedly affect child groups |
| **Child DG** | Site, segment, or application-specific policy and objects | Local exceptions accumulate and become harder to reason about |
| **Local firewall** | Emergency break-glass changes only, with cleanup after incident | Local objects collide with Panorama-managed objects and cause push failures |

### 4.4 Shared vs. Local Object Name Collisions

A firewall can contain local objects with the same names as Shared or device-group objects pushed from Panorama. The object names may match, but ownership and scope differ. Panorama cannot safely infer whether to overwrite, inherit, shadow, or preserve the local object.

**Collision example:**
- Local firewall object: `DNS-Server`
- Panorama Shared object: `DNS-Server`
- Device-group object: `DNS-Server`

**Result:** commit or push may fail with `duplicate object`, `already in use`, `invalid reference`, or `object conflict` errors.

| Action | Reason |
|---|---|
| Identify duplicates across Shared, parent DG, child DG, and local firewall | The same object name can exist in different ownership scopes |
| Decide the source of truth before cleanup | Renaming or deleting the wrong object can break references |
| Remove unnecessary local objects after migration to Panorama | A Panorama-managed firewall should not carry hidden local duplicates |
| Use scope-based prefixes where helpful | Names such as `SHARED_`, `GLOBAL_`, `REGION_`, `SITE_` reduce ambiguity |

### 4.5 Panorama Push Blocked by Firewall Settings

A managed firewall can be configured to block Panorama-pushed policy/object configuration or template configuration.

**Check on the firewall:**
- Go to **Device → Setup → Management → Panorama Settings**
- Confirm that **Panorama Policy and Objects** and **Device and Network Template** settings allow the expected pushes
- Commit locally if needed, then retry the Panorama push

### 4.6 Local Firewall Changes Causing Push Failures

A firewall can be Panorama-managed and still contain local modifications, overrides, renamed objects, or local policies. These local changes are a common reason that one firewall fails while the rest of the fleet accepts the push.

- Compare the firewall running configuration with the Panorama-rendered configuration
- Remove unnecessary local overrides
- Use Panorama as the source of truth wherever possible
- After emergency local changes, create a cleanup task immediately

### 4.7 Multi-VSYS and Shared Object Push Failures

Multi-vsys deployments increase the chance of object ownership and scoping problems. Avoid identical names between Shared objects and vsys-specific objects unless the behavior is intentional, documented, and validated.

---

## 5. Commit and Push Failure Modes (Deep Dive)

### 5.1 Partial Push Failures

A push job can succeed for some devices and fail for others. Panorama marks the job **partially failed**.

> **⚠ Always drill into push job details.** The summary task view shows Success / Failed / In-Progress. A partially failed push shows a mixed status. Navigate to **Monitor → Job Logs → [Job ID]** and inspect per-device results before declaring the push successful.

### 5.2 Object Dependency Errors

**Symptom:** `"Commit failed: object referenced but not found"` or `"value X is not valid"`

These occur when a policy in a device group references a shared or inherited object that does not exist at the resolution scope of the receiving device.

**Common causes:**
- **Missing shared object:** Object was created in a child device group but referenced by a policy in a parent, or vice versa
- **Renamed/moved objects:** An address object was renamed on Panorama but a policy still references the old name
- **Tag references:** Tags frequently forgotten — a security policy using a tag that exists only on the firewall's local config, not in Panorama's shared or device-group context

**Resolution Workflow:**
1. Run **Panorama → Commit → Validate**. Note all errors before attempting to fix.
2. For each missing object, identify whether it should live in Shared, the parent device group, or the device group in question.
3. Move or re-create the object at the correct scope.
4. Re-validate before committing.

### 5.3 Template vs. Device-Group Commit Scope Confusion

Template configuration (network interfaces, zones, routing) and device-group configuration (policies, objects) are **committed and pushed independently**. If you change an interface in a template but only push the device group, the interface change will not propagate.

> **⚠ Silent misconfiguration:** A firewall can silently run with a stale template and a current device group. Policy references zones defined in the template — if the template is outdated, zone names may mismatch, causing all traffic to hit the intrazone default action.

### 5.4 High-Availability Push Sequencing

When pushing to an HA pair, Panorama pushes to both peers. If the primary is rebooting or in a non-functional state, Panorama may report the push as **successful** because the secondary accepted it — but the primary will be **out of sync** post-failover.

```
# Always verify HA sync status on both peers after a push involving HA pairs
show high-availability all
# Confirm State is Active/Passive and Config is In Sync
# If primary was offline during push, re-push to the pair after primary recovers
```

### 5.5 Commit Locks and Configuration Locks

Panorama supports commit locks and configuration locks per administrator.
- A **configuration lock** prevents other admins from modifying the candidate config
- A **commit lock** prevents others from committing
- Both are per-Panorama-context (device group or template)

> **⚠ Stale locks block push windows.** If an admin disconnects without releasing locks, the locks persist until manually cleared by a superuser. Check: **Panorama → Locks**. Clear stale locks before beginning a push window.

---

## 6. Template Stack Precedence and Variables

### 6.1 Stack Resolution Order

| Template Position | Typical Use | Notes |
|---|---|---|
| **Top (highest precedence)** | Site-specific overrides (IP addresses, per-device settings) | Use template variables here |
| **Middle** | Regional or role-based settings (zone names, routing) | Shared across a subset of devices |
| **Bottom (lowest precedence)** | Global baseline (NTP, DNS, SNMP, syslog) | Applied to all devices in stack |

### 6.2 Template Variables

Template variables (`$variable_name` syntax) allow a single template to serve multiple devices with per-device substitution at push time. Variables are defined on the template stack and assigned per-device within the stack.

**Supported variable types:**
- IP Netmask (e.g., management IP, loopback address)
- IP Range
- FQDN
- Interface (physical interface name)
- Group ID (for OSPF/BGP processes)

> **⚠ Missing variable assignments fail silently until push.** If a device in the stack does not have a value assigned for a required variable, Panorama will attempt the push and the firewall will reject it with a validation error. Panorama's pre-push validation does not always catch missing variables — always audit variable assignments before a push window.

```
# Check template variable assignments via CLI
show template-stack name <STACK_NAME>
show template-stack name <STACK_NAME> variable
```

### 6.3 Template Stack Design Patterns

**Three-Layer Pattern (Recommended for Enterprise):**

| Layer | Purpose |
|---|---|
| Layer 1 — Device-Specific | Management IP, hostname, loopback IPs — all via template variables |
| Layer 2 — Role/Region | Zone definitions, routing protocols, VPN IPs for a region or device role |
| Layer 3 — Global Baseline | NTP servers, DNS resolvers, syslog/Cortex XDR profile, SNMP, login banner, password policy |

> **Keep zone names consistent across the stack.** If zone names differ between templates in the same stack (e.g., `untrust` vs `outside`), the firewall will have duplicate zones or fail validation. Establish a global zone naming convention and enforce it in your baseline template.

---

## 7. Device Group Hierarchy and Object Inheritance

### 7.1 Hierarchy Structure

Panorama supports up to four levels of device group nesting (including Shared). A firewall is a member of exactly one device group and inherits policy and objects from all ancestors up to Shared.

```
Shared (root — applies to all managed devices)
└─ Parent-DG (e.g., by region or customer)
   ├─ Child-DG-A (e.g., by site or function)
   │  └─ Firewall-1
   │  └─ Firewall-2
   └─ Child-DG-B
      └─ Firewall-3
```

### 7.2 Policy Inheritance and Evaluation Order

Security policies are evaluated top-to-bottom across the entire hierarchy. The effective policy on any firewall is a concatenation of policy rulesets from each ancestor:

| Position | Source | Typical Use |
|---|---|---|
| 1 (first evaluated) | Shared — Pre Rules | Block known bad (threat intel, global deny lists) |
| 2 | Parent DG — Pre Rules | Regional compliance blocks, customer-wide rules |
| 3 | Child DG — Pre Rules | Site-specific pre-rules |
| 4 | Device-Local Rules | Locally managed rules (rare in Panorama-managed environments) |
| 5 | Child DG — Post Rules | Site-specific cleanup / logging |
| 6 | Parent DG — Post Rules | Regional default deny with logging |
| 7 (last evaluated) | Shared — Post Rules | Global explicit deny-all with logging |

> **⚠ Pre vs. Post rule placement is irreversible without a reorder.** A rule placed in Shared Pre cannot be reordered below a Child DG rule without restructuring the hierarchy. Plan your pre/post strategy at design time: pre = enforcement that must always apply; post = defaults and catch-alls.

### 7.3 Shared vs. Device-Group Objects

**Resolution scope:** A policy in Child-DG-A can reference objects from Shared, its Parent-DG, and Child-DG-A itself. A policy in Child-DG-A **cannot** reference objects defined only in Child-DG-B. This is the most common misconfiguration in multi-customer Panorama deployments.

**Object overrides:** A child device group can override an inherited object by defining an object with the same name. The child's definition takes precedence for firewalls in that child group.

> **⚠ Object overrides are invisible in the parent view.** Panorama does not visually flag that a child is overriding a parent object. If you modify the parent object expecting all children to inherit the change, children with overrides will silently ignore the change. Audit child DGs for overrides before making parent-level object changes.

**Shared Object Design Guidelines:**

| Object Category | Recommended Scope |
|---|---|
| Global threat intel address groups | Shared |
| RFC 1918 / well-known address objects | Shared |
| Global application overrides | Shared |
| Security profiles (AV, Vulnerability, URL) | Shared or Parent DG |
| Site-specific server IPs | Child DG or via template variables |
| Customer/tenant-specific objects | Dedicated DG (never Shared in multi-tenant) |
| Tags used in DAGs | Shared if used across DGs; Child DG if local |

---

## 8. Offline / Air-Gapped PAN-OS Upgrades

In environments where Panorama and managed firewalls cannot access the internet, software and content updates must be staged manually. This is one of the most chronically mishandled operational procedures in Panorama-managed environments.

> **Critical sequencing rule:** Panorama should be upgraded **before** managed firewalls. Panorama must always be on the same version or higher than the managed firewalls. Never upgrade firewalls to a PAN-OS version newer than the Panorama version.

### 8.1 What Requires Internet Access by Default

| Update Type | Default Source |
|---|---|
| PAN-OS software images | updates.paloaltonetworks.com |
| Content updates (Antivirus, Threat, WildFire) | updates.paloaltonetworks.com |
| GlobalProtect client packages | updates.paloaltonetworks.com |
| Panorama software images | updates.paloaltonetworks.com |
| Log Collector software | Pushed from Panorama after Panorama updates |
| License activation | licensing.paloaltonetworks.com |

### 8.2 Offline Upgrade Workflow

**Step 1 — Download images to an internet-connected jump host**

```powershell
# Verify download integrity (Windows PowerShell)
Get-FileHash -Algorithm SHA256 .\PanOS_<model>-<version>.tgz
# Compare against hash listed on support portal
```

> **⚠ Model-specific images:** PAN-OS images are model-specific. The PA-3000 series image will not install on a PA-5000 series. For VM-series firewalls, the hypervisor variant matters (KVM vs. ESXi vs. Azure). Always verify the exact model string before downloading.

**Step 2 — Upload image to Panorama**

```
# Via web UI:
Panorama > Software > Upload → browse to the .tgz file

# Via SCP (if Panorama has SCP server enabled):
scp PanOS_<model>-<version>.tgz admin@<panorama-ip>:.
```

**Step 3 — Distribute from Panorama to managed devices**

When a firewall is managed by Panorama and Panorama has the image, the firewall fetches the image from Panorama via the management tunnel — **no internet required on the firewall**. This is the correct architecture for air-gapped deployments.

```
# Panorama > Managed Devices > Software
# Select the target image row
# Click 'Install' — select target devices
# Verify install status: Monitor > Job Logs > filter by Type = 'Install'
```

**Step 4 — Content updates (offline)**

Content packages (Antivirus, Threat Prevention, WildFire) follow the same pattern:
1. Download from support.paloaltonetworks.com → Dynamic Updates
2. Upload to Panorama: **Panorama → Dynamic Updates → Upload**
3. Install on managed devices: select uploaded package → Install → select devices

> **⚠ WildFire Inline ML requires cloud connectivity.** WildFire signature-based detection can run from locally cached packages, but Inline ML and real-time WildFire verdicts require connectivity to `wildfire.paloaltonetworks.com`. In fully air-gapped environments, a WF-Private appliance must be deployed.

**Recommended offline rollout order:**
1. Upgrade the passive Panorama HA peer first (if applicable)
2. Upgrade the active Panorama peer
3. Upgrade Log Collectors per vendor guidance
4. Upgrade a small firewall pilot group
5. Upgrade HA firewall pairs one peer at a time
6. Upgrade remaining firewalls by risk group and business priority
7. Post-upgrade validation; retain rollback artifacts until stability confirmed

### 8.3 Panorama Software Offline Upgrade

```
# File prefix: Panorama_pc-<version>
# Upload via web UI: Panorama > Panorama Software > Upload
# Install and reboot Panorama (15–30 minutes for M-series)
```

After Panorama comes back online: verify Log Collectors are still connected and push a test configuration to confirm management plane integrity.

### 8.4 Proxy Configuration for Semi-Restricted Environments

```
# Configure proxy on managed firewall:
# Device > Setup > Services > Proxy
Server: <proxy-hostname-or-ip>
Port: <port, typically 8080 or 3128>

# On Panorama (for its own update checks):
# Panorama > Setup > Services > Proxy
```

> **⚠ SSL inspection on proxy — certificate trust.** If the proxy performs SSL inspection, the proxy's CA certificate must be trusted by both Panorama and managed firewalls. Import the CA cert under **Panorama → Certificate Management → Certificates** and deploy to managed firewalls via template. Failure to do this causes `SSL handshake failed` errors that masquerade as network connectivity issues.

---

## 9. SAML-Based Admin Role Assignment (11.1.x)

Panorama 11.1.x introduced changes to how SAML authentication maps to administrator roles, particularly for custom admin roles. In practice, many failures are not login failures — they are **authorization failures** that appear when the admin tries to commit, push, select scope, or push changes made by another administrator.

### 9.1 SAML Authentication Flow

1. Admin initiates login; Panorama redirects to the IdP (e.g., Entra ID, Okta, Ping)
2. IdP authenticates the user and sends a SAML assertion back to Panorama
3. Panorama extracts the username from the NameID or a configured attribute
4. Panorama looks up the admin account by username
5. If the account exists, the pre-configured role on that account is applied
6. If role-based attribute mapping is configured, Panorama reads a SAML attribute to determine role — this **overrides** the static role on the account

### 9.2 Two Role-Assignment Models

#### Static Role Assignment (Pre-Provisioned Account)

The admin account is created in Panorama with a specific admin role profile before the user ever logs in. SAML only provides authentication — authorization is defined on the Panorama account.

| Pros | Cons |
|---|---|
| Simple to reason about; role is explicit | Manual provisioning required before first login |
| Works with all PAN-OS versions | No JIT provisioning |
| Predictable — SAML assertion content does not affect role | Scaling burden in large environments |

#### Attribute-Based Role Mapping (11.1.x)

Panorama 11.1.x supports mapping a SAML attribute value to an admin role profile.

```
# Panorama > Authentication Profile > SAML > Advanced
# Attribute to use for admin role: <IdP-defined attribute name>
# Example: 'panoramaRole' or 'adminRole'

# Panorama > Administrators > [account] > Admin Role Profile:
# Set to <Dynamic> to enable attribute-driven role assignment
```

> **⚠ 11.1.x Gotcha — Custom Admin Roles and Attribute Mapping:** Attribute-based mapping only works with built-in roles (superuser, deviceadmin, etc.) **OR** custom admin role profiles that are explicitly mapped. If the SAML attribute value does not **exactly** match a Panorama custom admin role profile name (case-sensitive), Panorama falls back to the static role on the account — it does **NOT** fail open or return an error. This means a misconfigured attribute mapping results in admins silently receiving incorrect (often elevated) privilege levels.

### 9.3 Configuration Reference — Entra ID as IdP

**Entra ID App Registration Claims:**
```
Claim name: panoramaRole
Source: Attribute
Value: user.assignedroles  (or a Group claim mapped to a role value)
# The value must exactly match the Panorama admin role profile name (case-sensitive)
```

**Panorama Authentication Profile (11.1.x):**
```
Panorama > Authentication Profile:
  Type: SAML
  IdP Metadata: <import from Entra ID>
  Username Attribute: NameID (or 'userprincipalname' if custom)
  Admin Role Attribute: panoramaRole   ← must match claim name exactly
  User Domain: (leave blank if UPN is used)

Panorama > Administrators:
  Username: <matches NameID/UPN>
  Authentication Profile: <SAML profile above>
  Admin Role Profile: <Dynamic>        ← enables attribute-based role
```

> **Do NOT set a static role when using `<Dynamic>`.** If the admin account has both `<Dynamic>` selected and a fallback static role, the behavior on attribute mismatch is the static role. For security-critical environments, set the fallback to the most restrictive custom role (read-only), not superuser.

### 9.4 Troubleshooting SAML Role Assignment Failures

| Symptom | Likely Cause & Resolution |
|---|---|
| Admin logs in but gets wrong permissions | Attribute value mismatch. Check exact case of claim value vs. Panorama role profile name |
| Admin cannot log in — "Authentication Failed" | NameID/username attribute mismatch. Verify Username Attribute setting matches what IdP sends |
| SAML assertion valid but Panorama rejects it | Clock skew > 60 seconds between Panorama and IdP. Verify NTP on Panorama |
| Attribute present in assertion but ignored | Panorama attribute name is case-sensitive. `'PanoramaRole'` ≠ `'panoramaRole'` |
| Works for built-in roles, fails for custom roles | Custom role profile name contains spaces or special characters. Use only alphanumeric and hyphens |
| IdP metadata import fails | Metadata XML has multiple certificates. Panorama 11.1.x requires a single signing certificate — remove extras |

### 9.5 Certificate Validation for SAML (11.1.x)

Panorama 11.1.x enforces stricter SAML certificate validation:

- **Sign Both Assertion and Response:** Panorama requires the assertion to be signed. Some IdPs default to signing only the response envelope. Set the IdP to sign both.
- **Certificate Expiry:** If the IdP's signing certificate rotates (common in Okta and Entra ID auto-rotation), re-import IdP metadata before the old cert expires. Panorama will reject assertions signed by the new cert if metadata hasn't been updated.

---

## 10. Log Collector Design — Dedicated vs. Mixed Mode

Log collector design is chronically under-documented. Two architectural decisions — mode selection and sizing — have long-term operational consequences that are **difficult to reverse** without a full log collector rebuild.

> **⚠ Mode change requires rebuild.** Switching a Panorama appliance between mixed mode and dedicated log collector mode is not a reconfiguration — it requires a factory reset and re-deployment. Plan the mode at initial deployment. The mode change deletes all stored logs.

### 10.1 Log Collector Modes

#### Dedicated Log Collector Mode

A Panorama instance deployed exclusively as a log collector — does not function as a Panorama management server.

| Characteristic | Value |
|---|---|
| Role | Log ingestion, storage, and forwarding only |
| Managed by | A separate Panorama management server |
| Log storage | All disk allocated to logs |
| Appropriate for | Large environments (>50 firewalls, high log volumes) |
| Minimum hardware | M-200 or M-500 recommended; M-100 EOL |

#### Mixed Mode (Panorama + Log Collector on Same Appliance)

A single Panorama instance functions as both the management server and a local log collector. This is the default mode for new Panorama deployments.

| Characteristic | Value |
|---|---|
| Role | Management + log collection on single appliance |
| Log storage | Shared between management and log storage — constrained |
| Appropriate for | Small-to-medium deployments (<20–30 firewalls, moderate log volume) |
| LPS penalty | ~50% of dedicated mode capacity (management overhead) |

> **Mixed mode LPS penalty:** Running Panorama in mixed mode imposes a significant LPS penalty because management plane processes compete with log collection for CPU and memory. For environments exceeding **15,000 LPS sustained**, dedicated mode is strongly recommended.

### 10.2 Collector Groups

- A Collector Group operates as a logical logging unit and can include multiple managed collectors
- **Redundancy:** Logs are written to 2 collectors — doubles storage requirements but protects against single collector failure
- **Distribution:** Logs distributed across collectors using consistent-hashing by source device serial number
- A firewall can belong to **only one collector group**
- **Avoid two-collector designs** for critical logging requirements — at least three collectors preferred where HA and split-brain avoidance matter

### 10.3 Sizing Methodology

**Required inputs:**
- Average and peak logs per second (LPS) per firewall
- Average log entry size (~500 bytes for traffic logs; ~1–2 KB for threat logs)
- Retention requirement (days)
- Number of managed firewalls
- Log types enabled (Traffic, Threat, URL, WildFire, Auth, Data, etc.)
- Redundancy requirement

**Storage formula:**

```
Storage (TB) = LPS_peak × avg_log_size_bytes × seconds_per_day × retention_days
               ──────────────────────────────────────────────────────────────────
                                    1,000,000,000,000

Then apply:
  × Redundancy Factor (1 = no redundancy; 2 = redundant logging)
  × Growth Factor (1.25 to 1.50 minimum)
```

**Example:**
```
LPS_peak = 10,000 logs/sec
avg_log_size = 600 bytes
retention = 90 days

Storage = 10,000 × 600 × 86,400 × 90 / 1e12 = 46.7 TB
× 2 (redundancy) × 1.3 (growth) = ~121 TB
+ 20% index overhead = ~145 TB required
```

An environment with this profile requires a **dedicated Log Collector architecture**, external log storage strategy, or SIEM/cloud logging design.

**M-Series Log Collector Hardware Reference:**

| Model | Raw Log Disk (approx.) | Status |
|---|---|---|
| M-100 | ~4 TB | **End of Life — do not deploy** |
| M-200 | ~8 TB (expandable) | Current — small/medium |
| M-500 | ~16 TB | Current — medium/large |
| M-600 | ~24 TB | Current — large |
| M-700 | ~24–96 TB (SSD options) | Current — high-performance, large scale |
| VM-Series | Limited by hypervisor disk | Add virtual disks up to platform limits |

**Throughput Limits:**

| Collector Model | Max LPS (approx.) |
|---|---|
| M-200 (dedicated mode) | ~30,000 LPS |
| M-500 (dedicated mode) | ~60,000 LPS |
| M-700 (dedicated mode) | ~100,000+ LPS |
| Mixed mode (any model) | ~50% of dedicated mode capacity |

### 10.4 Operational Considerations

**Disk quotas by log type** — default quotas favor traffic logs. Recommended starting point for security-focused environments:

```
Traffic: 30%
Threat: 25%
URL Filtering: 15%
WildFire: 10%
Data: 10%
Auth: 5%
Other: 5%
# Configure: Panorama > Collector Groups > [Group] > Log Storage
```

**Log Collector software version:** Always upgrade Panorama first, then push the upgrade to log collectors. Log collectors reboot during upgrade — during this window, logs are dropped unless a redundant collector in the group takes over. Collector group redundancy must be pre-configured before upgrades.

---

## 11. Troubleshooting Workflow

**Step 1 — Identify the failed operation:** Determine whether the failure occurred during Validate, Commit to Panorama, Commit and Push, Push to Devices, Collector Group push, or software/content deployment.

**Step 2 — Read the job details:** Review Tasks, commit job details, system logs, config logs, target firewall job status. Capture exact error text.

**Step 3 — Commit to Panorama only:** If this fails, troubleshoot Panorama candidate configuration, roles, locks, storage, plugins, or validation. If it succeeds, move to push-specific analysis.

**Step 4 — Validate push scope:** Check device group, template stack, child device group inclusion, HA peer selection, vsys selection, and Collector Group selection.

**Step 5 — Push to one firewall:** Select one target, push only the affected scope, read the job result, fix errors, then expand to the HA pair and broader estate.

**Step 6 — Check firewall Panorama settings:** Confirm the firewall is connected to Panorama and accepts policy/object and template pushes (**Device → Setup → Management → Panorama Settings**).

**Step 7 — Check object collisions:** Search for duplicate names across Shared, parent DG, child DG, local firewall config, and vsys-specific objects.

**Step 8 — Check admin role authorization:** If only one admin is affected, compare SAML attributes, access domains, custom role permissions, Managed Devices, Push All Changes, and Push For Other Admins.

**Step 9 — Check version, content, and plugin compatibility:** Verify Panorama, firewall, Log Collector, plugin, and content versions.

### Common Error Text to Search For

```
invalid reference
already in use
duplicate
not a valid reference
object not found
template stack
device group
shared vsys
permission denied
not authorized
out-of-sync
```

---

## 12. Fast Decision Tree

```
Did Commit to Panorama fail?
├─ Yes → Candidate config, references, locks, storage, role, plugin, or validation issue
└─ No → Continue

Did Push to Device fail?
├─ Yes → Target rendering, connectivity, object collision, local override, version mismatch, or role issue
└─ No → Continue

Did push succeed but behavior is wrong?
├─ Yes → Hierarchy, rule order, template precedence, local override, or wrong target scope
└─ No → No immediate Panorama fault

Does issue affect only one admin?
├─ Yes → SAML/custom admin role/access domain/push permission issue
└─ No → Continue

Does issue affect only one firewall?
├─ Yes → Local firewall config, duplicate object, mode mismatch, connectivity, or HA peer difference
└─ No → Shared design, parent DG, template stack, content, plugin, or Panorama-wide issue

Does issue affect logging or collectors?
├─ Yes → Collector Group, disk, redundancy, compatibility, collector health, or sizing issue
└─ No → Continue standard commit/push triage
```

---

## 13. Preventive Checklists

### Before Major Panorama Changes

- [ ] Export Panorama config
- [ ] Export firewall configs for high-risk devices
- [ ] Confirm no pending local firewall changes
- [ ] Confirm managed devices are connected
- [ ] Confirm HA peers are healthy
- [ ] Confirm content versions are compatible
- [ ] Validate template stack order
- [ ] Validate device-group hierarchy
- [ ] Run Preview Changes
- [ ] Push to a pilot device first

### Before Offline Upgrades

- [ ] Download all required images and content from support portal
- [ ] Verify SHA256 hash before staging
- [ ] Confirm upgrade path and release notes reviewed
- [ ] Confirm plugin compatibility
- [ ] Confirm Panorama can manage the firewall target version
- [ ] Upgrade Panorama before firewalls
- [ ] Upgrade Log Collectors per plan
- [ ] Test a small firewall group first
- [ ] Confirm Panorama-firewall security policy allows required management communication after upgrade

### Before SAML Admin Rollout

- [ ] Confirm IdP sends correct role and access-domain attributes
- [ ] Test login
- [ ] Test Commit to Panorama
- [ ] Test Push to Devices
- [ ] Test Push For Other Admins
- [ ] Test template and device-group scope selection
- [ ] Keep local break-glass access
- [ ] Review PAN-OS 11.1.x release notes for custom-role behavior changes

### Before Log Collector Deployment

- [ ] Measure logs per second (LPS) per firewall
- [ ] Measure daily GB/TB generated
- [ ] Define retention requirement
- [ ] Define redundancy requirement
- [ ] Calculate storage using the formula in Section 10.3
- [ ] Decide local vs. dedicated collector based on measured data
- [ ] Avoid two-collector designs for critical environments
- [ ] Validate Collector Group health
- [ ] Configure quotas and expiration periods

---

## 14. Escalation Data to Collect

| Collect | Why |
|---|---|
| Panorama version, firewall version, content version, plugin versions | Confirms compatibility and known issue exposure |
| Panorama mode (Panorama, Management Only, or Log Collector) | Identifies the appliance role |
| Exact commit/push error and failed job ID | Preserves failure evidence and avoids guesswork |
| Affected device group and template stack | Identifies the hierarchy and rendered config path |
| Affected firewall serial numbers | Shows whether problem is device-specific or systemic |
| Admin account and role used | Determines whether issue is authorization-specific |
| Duplicate local/Shared/DG object evidence | Confirms or rules out object collision |
| Collector Group design and mode | Needed for logging or collector-related issues |

### Useful CLI Commands

```
# On Panorama:
show jobs all
show jobs id <job-id>
show system info
show system disk-space
show devices all

# On affected firewalls:
show jobs all
show system info
show panorama-status
```

---

## 15. References

| Reference | URL |
|---|---|
| Preview, validate, or commit configuration changes | https://docs.paloaltonetworks.com/panorama/10-2/panorama-admin/administer-panorama/preview-validate-or-commit-configuration-changes |
| Troubleshoot commit failures | https://docs.paloaltonetworks.com/panorama/10-2/panorama-admin/troubleshooting/troubleshoot-commit-failures |
| Configure a template stack | https://docs.paloaltonetworks.com/panorama/10-1/panorama-admin/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack |
| Device group hierarchy | https://docs.paloaltonetworks.com/panorama/10-2/panorama-admin/panorama-overview/centralized-firewall-configuration-and-update-management/device-groups/device-group-hierarchy |
| Troubleshoot template or device group push failures | https://docs.paloaltonetworks.com/content/techdocs/en_US/panorama/11-0/panorama-admin/troubleshooting/troubleshoot-commit-failures/troubleshoot-template-or-device-group-push-failures |
| Deploy updates to firewalls when Panorama is not internet-connected | https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-upgrade/upgrade-panorama/deploy-updates-to-firewalls-log-collectors-and-wildfire-appliances-using-panorama/deploy-an-update-to-firewalls-when-panorama-is-not-internet-connected |
| Configure SAML authentication for Panorama administrators | https://docs.paloaltonetworks.com/panorama/10-1/panorama-admin/set-up-panorama/set-up-administrative-access-to-panorama/configure-administrative-accounts-and-authentication/configure-saml-authentication-for-panorama-administrators |
| PAN-OS 11.1 known and addressed issues | https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-release-notes |
| Local and distributed log collection | https://docs.paloaltonetworks.com/content/techdocs/en_US/panorama/10-1/panorama-admin/panorama-overview/centralized-logging-and-reporting/local-and-distributed-log-collection.html |
| Managed collectors and collector groups | https://docs.paloaltonetworks.com/panorama/10-1/panorama-admin/panorama-overview/centralized-logging-and-reporting/managed-collectors-and-collector-groups |
| Determine Panorama log storage requirements | https://docs.paloaltonetworks.com/panorama/10-1/panorama-admin/set-up-panorama/determine-panorama-log-storage-requirements |

---

*End of Article KB-PAN-MGMT-001*
