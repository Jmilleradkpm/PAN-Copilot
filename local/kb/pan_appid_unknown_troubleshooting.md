# KB: App-ID `unknown-tcp` and `unknown-udp` — Causes, Fixes, and the Custom App-ID Lifecycle

**Article ID:** KB-PAN-APPID-001
**Revision:** 2.0 — Consolidated

| Field | Value |
|-------|-------|
| **Article Owner** | Network Security Engineering |
| **Primary Platform** | Palo Alto Networks NGFW / PAN-OS / Panorama |
| **Applies To** | PAN-OS 10.0 / 10.1 / 10.2 / 11.0 / 11.1 / 11.2; Panorama-managed and standalone NGFW |
| **Audience** | Firewall engineers, SOC analysts, NOC escalation, PCNSE candidates |
| **Severity** | P1 (production traffic dropping — PAN-303959), P2 (custom application broken), P3 (visibility gap) |
| **Last Reviewed** | May 10, 2026 |
| **Known Issue** | PAN-303959 fixed in PAN-OS **11.2.11**, **11.2.7-h10**, and **11.2.10-h3**. Evaluate upgrade path before building workaround policy on affected releases. |

> **Executive summary:** `unknown-tcp` and `unknown-udp` are not one problem. They are labels that mean the firewall did not have a specific App-ID for the session at the point policy and logging were applied. The correct fix depends on why identification failed: not enough data, proprietary or internal protocol, missing signature, encryption or decryption limits, asymmetric traffic, policy design, custom signature quality, application override misuse, or a PAN-OS defect such as PAN-303959 on affected 11.2.x releases.

> **Core rule:** Treat `unknown-tcp` and `unknown-udp` as evidence to investigate — not as the diagnosis. The investigation must answer: did the firewall lack data, lack a signature, lack visibility, lack symmetric traffic, hit a software defect, or get forced into a Layer 4 override path?

> **Two outcomes to prevent:** Blindly allowing unknown traffic creates a persistent security blind spot and an exfiltration path. Blindly blocking unknown traffic breaks legitimate business applications before engineers have identified the actual protocol. Neither response is acceptable without first determining the cause.

---

## Contents

1. Problem Statement and Scope
2. How App-ID Classification Works — the Full Lifecycle
3. Definitions
4. Known Issue: PAN-303959
5. Common Symptoms
6. Root-Cause Matrix
7. Incident Triage Workflow
8. Root Cause 1 — No Matching App-ID Signature
9. Root Cause 2 — SSL/TLS Encryption Blocking App-ID Visibility
10. Root Cause 3 — Insufficient Packets or Short Sessions
11. Root Cause 4 — PAN-303959: App-ID Resource Exhaustion in PAN-OS 11.2.x
12. Root Cause 5 — Asymmetric Traffic and Non-SYN-TCP
13. Root Cause 6 — Genuinely Unknown or Anomalous Traffic
14. Policy Logic Traps Involving Unknown Traffic
15. Packet Capture Workflow for Unknown Applications
16. The Decision Tree: Unknown → Custom Signature → Application Override
17. Custom App-ID Signature Lifecycle
18. Application Override — What It Is, What It Breaks, When to Use It
19. Policy Design for Unknown Traffic
20. Special Cases
21. App-ID and Security Profile Interaction with Unknown Traffic
22. Monitoring and Alerting on Unknown Application Traffic
23. Fix Playbooks
24. Operational Guardrails
25. Quick Decision Table
26. Known Traps and Exact Fixes
27. CLI and GUI Diagnostic Reference
28. Change-Control Checklist
29. Escalation Bundle
30. PCNSE-Style Quick Answer Key
31. References
32. Revision History

---

## 1. Problem Statement and Scope

`unknown-tcp` and `unknown-udp` appear in traffic logs when the App-ID engine cannot classify a session into a named application. This happens constantly in production environments — for legitimate internal applications, encrypted sessions that can't be inspected, proprietary protocols, and occasionally for well-known applications that are broken, tunneling through unusual ports, or hitting an App-ID engine resource constraint.

The problem is multi-dimensional:

**Visibility:** Unknown traffic bypasses application-aware policy. A rule that allows `web-browsing` will not match `unknown-tcp`, and a rule that allows `unknown-tcp` provides no application-layer context for threat profiles, URL filtering, or reporting.

**Security:** Unknown traffic is a known evasion vector. Attackers use custom protocols, tunneling, and non-standard ports specifically to appear as `unknown-tcp` and evade inspection.

**Operational (PAN-303959):** On affected PAN-OS 11.2.x releases, legitimate traffic that would ordinarily be identified correctly is prematurely classified as `unknown-tcp`/`unknown-udp` due to an App-ID resource leak, then eventually dropped. This is a production-impact bug with specific fix versions and interim workarounds. Importantly, custom signatures or application overrides may suppress the symptom without removing the underlying resource leak — an upgrade is the correct fix.

**Policy debt:** Most environments have a blanket allow rule for `unknown-tcp` that was added "temporarily" and never revisited. Over time it becomes the primary path for uninspected traffic.

This article covers every aspect of this problem: how to determine which root cause applies, the PAN-303959 known issue, the lifecycle from unknown to custom signature to override, writing custom App-ID signatures, application override tradeoffs, policy architecture, and monitoring.

---

## 2. How App-ID Classification Works — the Full Lifecycle

### Session classification sequence

```
1.  First packet arrives → session created
2.  App-ID engine begins inspection
        Initial: proto-based (tcp/udp) → port heuristic → signature scan
3.  If signature matches on early packets:
        Application identified → security rule matched → session continues
4.  If no signature match yet:
        Application = "incomplete" while more packets are collected
5.  After content timeout (default: 5 seconds):
        If identified → update App-ID on session → re-evaluate security policy
        If not identified → classified as unknown-tcp or unknown-udp
6.  Security policy applied based on final App-ID
7.  If unknown-tcp/udp not explicitly allowed → session reset or denied
```

### Key timing values

| Parameter | Default Value | Meaning |
|-----------|--------------|---------|
| Application content timeout | 5 seconds | How long App-ID waits for enough packets to classify |
| Session timeout (unknown-tcp) | 30 seconds | How long an `unknown-tcp` session lives before aging out |
| Application timeout | Varies by app | How long an idle named session is kept |
| App-ID update interval | Per content update | Frequency of new App-ID signature delivery |

### The classification hierarchy

App-ID uses multiple methods in order. Lower methods are less reliable:

```
1. Application signatures       — byte patterns, protocol state machines, behavioral heuristics
2. Application protocol decoder — RFC-conformant protocol parsing (HTTP, DNS, FTP, etc.)
3. Heuristics                   — statistical analysis (port, behavior, packet size distribution)
4. SSL/TLS metadata             — SNI, certificate subject/SAN (without decryption)
5. Port-based fallback          — used only when all other methods fail
```

### When App-ID can and cannot classify

| Condition | App-ID Result |
|-----------|---------------|
| Known application, sufficient packets, plaintext or decrypted | Named application (`zoom`, `web-browsing`, etc.) |
| Known application, encrypted, identifiable from TLS metadata | Named application (limited confidence) |
| Known application, encrypted, not identifiable from metadata | `ssl` — not the specific application |
| Unknown application, plaintext | `unknown-tcp` / `unknown-udp` |
| Unknown application, encrypted | `ssl` (cannot go deeper without decryption) |
| Too few packets before session closes | `incomplete` → may age as `unknown-tcp` |
| App-ID resource exhaustion (PAN-303959) | `unknown-tcp` / `unknown-udp` prematurely |
| Asymmetric routing — one direction only visible | `non-syn-tcp` or `unknown-tcp` |

---

## 3. Definitions

| Term | Meaning | Operational Interpretation |
|------|---------|---------------------------|
| `unknown-tcp` | TCP session that did not receive a specific App-ID | Common with proprietary apps, insufficient data, incomplete sessions, scans, short-lived flows, custom protocols, or App-ID defects |
| `unknown-udp` | UDP session that did not receive a specific App-ID | Common with custom UDP protocols, proprietary telemetry, short-lived flows, UDP/443 variants, IoT, or vendor-specific apps |
| `non-syn-tcp` | TCP flow observed without expected SYN establishment | Indicates asymmetric routing, midstream pickup, HA failover, session rematch after path change, or captures taken after session establishment |
| `incomplete` | Session ended before App-ID finished classifying | Not the same as `unknown-tcp`. Often scans, health checks, or failed connection attempts — session too short, not classification failure |
| `ssl` / `web-browsing` | Broad App-IDs for encrypted TLS or generic web traffic | Not the same as unknown, but part of the same policy trap when a more specific App-ID later appears or fails to appear |
| `insufficient-data` | Session had too few packets for any classification | Single-packet flows; extreme case of the short-session problem |
| Custom App-ID signature | Local application definition based on matching traffic patterns | Preferred fix for recurring internal/proprietary applications when a reliable pattern can be built |
| Application override | Policy mechanism that forces traffic to a specified application name by Layer 3/Layer 4 match | Last-resort fix — bypasses normal Layer 7 App-ID processing and reduces threat inspection fidelity |

---

## 4. Known Issue: PAN-303959

> **Current fix status:** PAN-303959 is fixed in PAN-OS **11.2.11**, **11.2.7-h10**, and **11.2.10-h3**. If running an affected 11.2.x release where traffic is incorrectly classified as `unknown-tcp`/`unknown-udp` and eventually drops, evaluate the upgrade path first — before building workaround policy. [S1][S2]

PAN-303959 is not the normal condition where an internal application has no signature. It is a defect pattern: an App-ID resource leak causes traffic to be incorrectly classified as `unknown-tcp` or `unknown-udp`, and those sessions eventually drop. The distinction matters because a custom signature or application override may suppress the symptom without fixing the resource leak.

### PAN-303959 classification questions

| Question | Use This Answer to Classify the Issue |
|----------|---------------------------------------|
| Is the firewall running an affected 11.2.x build? | Check the exact PAN-OS release and hotfix against Palo Alto release notes. If prior to 11.2.11, 11.2.7-h10, or 11.2.10-h3 — PAN-303959 must remain in scope |
| Does the problem worsen over time until traffic drops? | More consistent with a resource-leak defect than a static missing signature |
| Does clearing sessions temporarily help? | Temporary relief may support a resource or state issue — not a durable fix |
| Does the same traffic identify correctly on a fixed version? | Supports PAN-303959 or another software defect rather than application design |
| Is only one proprietary application always unknown but stable (not degrading)? | More likely a missing/custom App-ID problem than PAN-303959 |

---

## 5. Common Symptoms

- Traffic log shows `application = unknown-tcp` or `unknown-udp`
- Rulebase has an allow rule for the intended application, but traffic hits an unknown deny or the default deny
- Traffic is initially allowed as `ssl` or `web-browsing`, then later blocked when App-ID re-identifies it as a more specific App-ID not present in policy
- Internal application works when security policy uses service/port, but fails when policy requires a named application
- UDP-based application shows `unknown-udp` even though the port is correct and routing is verified
- Traffic drops after running for hours or days on a PAN-OS 11.2.x release affected by PAN-303959
- Custom App-ID signature matches too broadly, too narrowly, or not at all
- Application override restores connectivity but Threat, URL, File Blocking, Data Filtering, or App-ID visibility disappears or degrades
- ACC reports large volumes of unknown traffic from specific hosts, IoT networks, OT environments, backup systems, or custom business applications

---

## 6. Root-Cause Matrix

| Root Cause | Typical Signal | Why It Happens | Correct Fix |
|---|---|---|---|
| Incomplete data | Handshake occurs but no payload before timeout | App-ID has no application data to classify | Validate source intent; if scan or health check — control by policy, not signature |
| Insufficient data | Small payload appears but not enough to match | Protocol does not expose a stable pattern early enough | Capture more sessions; build custom signature if a reliable pattern exists |
| Commercial app with no App-ID | Repeatable unknown traffic to known vendor endpoint | Palo Alto content has no predefined signature yet | Submit packet capture to Palo Alto for App-ID development; use scoped temporary policy |
| Internal / proprietary app | Unknown traffic between known internal systems | No public signature exists | Create custom App-ID signature with parent app where possible |
| Encrypted or opaque custom protocol | TLS or custom encryption prevents payload visibility | No decrypted or visible pattern exists for signature matching | Use certificate/SNI/port/IP policy, decryption if supportable, or app override as last resort |
| Asymmetric traffic / non-syn-tcp | Firewall sees only one direction or midstream packets | App-ID cannot evaluate the complete session | Fix routing, PBF, ECMP, HA flow ownership, or session synchronization |
| UDP short-lived behavior | Single request/response or sparse UDP packets | UDP has no handshake; may not provide enough identifying data | Use packet capture, session timeout tuning, or custom UDP signature if stable |
| App-ID dependency missing | Specific app allowed but parent/base/dependency blocked | Application depends on `ssl`, `web-browsing`, base apps, or another protocol | Resolve explicit dependencies; validate implicit support behavior |
| Content update changed App-ID | Traffic that was `ssl`/`web-browsing`/`unknown` becomes specific App-ID and policy blocks it | New or modified App-ID changes policy match | Use App-ID Update Safeguard as transition; update policy intentionally |
| Bad custom signature | App remains unknown or unrelated traffic matches custom app | Wrong context, weak pattern, wrong parent, wrong scope, missing transaction coverage | Redesign signature using multiple captures and validation |
| Application override misuse | Traffic works but Layer 7 controls disappear or change | Override bypasses normal App-ID processing | Use only for last-resort cases; prefer custom App-ID; govern override tightly |
| PAN-303959 | Affected 11.2.x build; traffic incorrectly unknown and eventually drops | App-ID resource leak | Upgrade to 11.2.11, 11.2.7-h10, or 11.2.10-h3 — not a policy problem |

---

## 7. Incident Triage Workflow

### Step 1 — Collect minimum evidence

- [ ] Firewall hostname, serial, model, virtual system, and PAN-OS version (exact build and hotfix)
- [ ] Applications and Threats content version and install time
- [ ] Source IP, source user, source zone, destination IP, destination zone, destination port, and protocol
- [ ] Traffic log fields: application, rule, action, session end reason, bytes sent/received, packets sent/received, NAT source/destination, URL category, session ID, repeat count
- [ ] Whether the same traffic was previously identified as `ssl`, `web-browsing`, or a named App-ID
- [ ] Whether the issue is isolated to one app, one subnet, one firewall, one HA member, one path, one content version, or one PAN-OS version
- [ ] A packet capture from the firewall or SPAN/tap point that includes the beginning of the session

### Step 2 — Characterize the unknown traffic pattern

Filter traffic logs and aggregate results:

```
Monitor → Logs → Traffic
Filter: app eq unknown-tcp OR app eq unknown-udp
Columns: Source, Destination, Destination Port, From Zone, To Zone,
         Rule, Bytes, Sessions, Packets, Session Duration
```

Mental bucketing:

| Pattern | Likely Category |
|---------|----------------|
| Few sources, same destination, same port | Specific internal application |
| Few sources, many destinations, many ports | Scanner or misconfigured host |
| Many sources, same destination, same port | Unrecognized cloud service or SaaS |
| Many sources, many destinations, many ports | Mixed problems — requires per-flow analysis |
| Sudden spike, then degrading traffic and eventual drops | PAN-303959 candidate |
| Consistent baseline, same systems daily | Known internal app without a signature |

### Step 3 — Determine normal unknown behavior vs. defect

| Observation | Likely Category | Next Step |
|-------------|----------------|-----------|
| Handshake completed; no payload followed | Incomplete data | Check whether source is scanning, health checking, or failing before sending data |
| Payload exists but too short or sparse | Insufficient data | Capture more examples; inspect protocol pattern stability |
| Same unknown app every day between same systems | Internal/custom application | Build custom App-ID or submit App-ID request if commercial |
| Traffic is one-way or shows `non-syn-tcp` | Path/session visibility problem | Fix asymmetric routing or HA ownership before tuning App-ID |
| Unknown classification increases after upgrade and traffic eventually drops | PAN-303959 candidate | Check affected release; plan upgrade/hotfix path |
| Override makes it work but inspection is reduced | Application override side effect | Replace override with custom App-ID if feasible |

### Step 4 — Apply the root cause decision tree

```
Is this PAN-OS 11.2.x (pre-11.2.11 / pre-11.2.7-h10 / pre-11.2.10-h3)?
  └── YES → Check App-ID resource counters (Section 11) → if exhaustion: PAN-303959
  └── NO  → continue

Is traffic one-way or showing non-syn-tcp?
  └── YES → Asymmetric routing / HA issue (Section 12) — fix path before App-ID
  └── NO  → continue

Is the traffic encrypted (TLS)?
  └── YES → Is decryption enabled?
        └── NO  → Root Cause 2 (Section 9)
        └── YES → Short session? → Root Cause 3 (Section 10)
  └── NO  → continue

Does the App-ID database have a signature?
  └── YES → Short session? → Root Cause 3 (Section 10)
            Check content version — signature may be newer
  └── NO  → continue

Is this a known internal/proprietary application?
  └── YES → Packet capture available? → Custom signature (Section 17) — preferred
            No packet capture → App override (Section 18) — temporary
  └── NO  → Anomalous traffic (Section 13) — block and investigate
```

### Step 5 — CLI and operational checks

```
show system info
show system software status
show system resource
show running application setting

# Check current sessions with unknown classification
show session all filter source <source-ip> destination <destination-ip>
show session all filter application unknown-tcp
show session id <session-id>

# App-ID and resource counters (before/after a reproduction window)
show counter global filter delta yes | match unknown
show counter global filter delta yes | match appid
show counter global filter delta yes | match resource
show counter global filter aspect app-id delta yes

# Confirm content version
show system content-version
```

> **Counter note:** The exact counter names that matter vary by platform and release. Use counters as supporting evidence, not as the sole diagnosis. If a software defect is suspected, collect tech support files before clearing sessions or rebooting.

---

## 8. Root Cause 1 — No Matching App-ID Signature

### Confirming no signature exists

```
# Search by name or keyword
show application | match <application-keyword>

# Search by port
show application | match <port-number>

# Check App-ID database online
# https://applipedia.paloaltonetworks.com

# Check if a content update would add it
show system content-version
request system content upgrade check
```

If the application exists in Applipedia but not on your firewall, you may be running an older content version:

```
request system content upgrade install
```

### Options when no signature exists

Choose based on the traffic's trust level and whether App-ID visibility matters:

| Option | What It Preserves | What It Loses | When to Use |
|--------|------------------|---------------|-------------|
| Allow `unknown-tcp` on a scoped rule | Full session logging | App-ID-based policy; full threat profile inspection | Temporary only — with a documented review date |
| Write a custom App-ID signature | Full policy control; complete threat profile inspection | Nothing — this is the best long-term option | When you have packet captures and understand the protocol |
| Application override | Named application in logs | App-ID engine; most content inspection | Short-lived sessions where signatures can't trigger; last resort only |

---

## 9. Root Cause 2 — SSL/TLS Encryption Blocking App-ID Visibility

### Why encryption prevents classification

When traffic is encrypted and SSL decryption is not enabled, App-ID sees only TLS ClientHello metadata (SNI, offered ciphers) and server certificate fields (subject, SAN, issuer). For many modern applications this metadata is sufficient. For others — especially custom internal applications, apps behind CDNs with wildcard certificates, or apps using non-standard TLS ports — it is not. The session classifies as `ssl` (not `unknown-tcp`).

`unknown-tcp` on an encrypted session means App-ID couldn't match even TLS metadata. This happens when:
- The application uses a self-signed or internal CA cert without recognizable fingerprints
- The application uses non-standard TLS ports
- The application uses non-standard SNI or no SNI

### Resolution

With SSL Forward Proxy decryption enabled, App-ID can inspect the decrypted payload and apply its full signature library. An application showing as `ssl` or `unknown-tcp` without decryption will often resolve to its named application with decryption.

```
# Check if decryption is enabled for the relevant traffic
show running decryption-policy

# Check decryption log for this session
Monitor → Logs → Decryption
Filter: addr.src in <source> and addr.dst in <destination>
```

Refer to KB-PAN-DEC-001 for full SSL decryption configuration and troubleshooting.

### When you cannot or should not decrypt

For traffic that cannot be decrypted (pinned certs, mTLS, compliance): use the application `ssl` as the App-ID in a scoped security rule (zone + address scoped), or write a custom App-ID signature based on TLS metadata using the `ssl-cert-subject` or `ssl-cert-issuer` context (see Section 15).

---

## 10. Root Cause 3 — Insufficient Packets or Short Sessions

### How session length affects App-ID

App-ID needs a minimum amount of application-layer data to classify a session. Short-lived sessions — health checks, connection tests, brief API calls, UDP request/response cycles — may not produce enough packets before they close. When the session closes before App-ID finishes, the final classification is `unknown-tcp` (or `incomplete` if very early).

### Detecting this root cause

```
Monitor → Logs → Traffic
Columns: Packets Sent, Packets Received, Bytes Sent, Bytes Received, Session Duration
```

Short-session indicators:
- Packet count < 5 on either side
- Session duration < 2 seconds
- Total bytes < 500

### UDP-specific behavior

UDP has no TCP-style handshake, and many UDP applications send sparse or short payloads. A single UDP packet may not contain enough data for reliable classification. Troubleshoot UDP unknowns with repeated transaction captures and validate whether `application-default`, custom timeout, or a custom UDP signature is feasible.

### Resolution

**Option A — Application override (for tightly scoped known flows):** For known applications with consistently short sessions (load balancer health checks, single-packet probes), override tells the firewall to skip App-ID scanning and immediately assign a named application. See Section 18 for full tradeoffs.

**Option B — Scoped allow for `incomplete` / `unknown-tcp`:** Rather than overriding, scope a rule tightly (specific source, destination, port) to allow these classifications without a blanket permit.

**Application content timeout tuning (rarely the right answer):**

```
# Check current setting
show running application-content-timeout

# Adjust (range: 1–3600 seconds)
set deviceconfig setting application-content-timeout <seconds>
```

> **Caution:** Increasing content timeout increases resource consumption. On high-traffic firewalls, aggressive increases can contribute to the resource exhaustion pattern described in Section 11.

---

## 11. Root Cause 4 — PAN-303959: App-ID Resource Exhaustion in PAN-OS 11.2.x

### Issue description

PAN-303959 is a defect in PAN-OS 11.2.x where the App-ID internal resource pool is exhausted under certain traffic conditions. When exhausted:

1. The App-ID engine cannot complete signature scanning for new sessions
2. New sessions are prematurely classified as `unknown-tcp` or `unknown-udp`
3. Sessions then match whatever rule applies to those classifications
4. In environments where `unknown-tcp` is denied (correct posture), legitimate traffic drops

The defect is in the App-ID scanning resource pool — not memory, CPU, or session table capacity. A firewall can have abundant capacity elsewhere and still hit this condition.

### Affected versions and fix status

| PAN-OS Version | PAN-303959 Status |
|---|---|
| 11.2.x (pre-fix releases) | **Affected** |
| **11.2.11** | **Fixed** [S1] |
| **11.2.7-h10** | **Fixed** [S1] |
| **11.2.10-h3** | **Fixed** [S1] |
| 11.1.x and earlier | Not affected |

> **Always verify current fix status at the official Palo Alto release notes** — search for PAN-303959. Do not rely solely on this KB; Palo Alto updates fix information as hotfixes are released.

### Detection and confirmation

**Step 1 — Confirm PAN-OS version:**

```
show system info | match version
```

If not on 11.2.x, this root cause does not apply.

**Step 2 — Check App-ID resource counters:**

```
show counter global filter aspect app-id delta yes
show counter global filter delta yes | match appid_resource
show counter global filter delta yes | match app_resource_alloc_fail
show counter global filter delta yes | match resource
```

A consistently incrementing App-ID resource counter indicates resource exhaustion. The exact counter name varies by sub-release — check with TAC for your specific build if uncertain.

**Step 3 — Correlate with traffic log spike:**

```
Monitor → Logs → Traffic
Filter: app eq unknown-tcp
Sort by: receive_time
```

If `unknown-tcp` sessions spike without a corresponding change in actual traffic patterns and App-ID resource counters are incrementing — PAN-303959 is the likely cause.

**Step 4 — Check ACC for reclassification:**

If normally-named applications suddenly disappear from the ACC Application tab and appear as `unknown-tcp` without any network change, resource exhaustion has shifted those sessions out of named classification.

### Workarounds on affected versions (pending upgrade)

> **Do not address PAN-303959 exclusively with local policy workarounds.** They suppress the symptom without fixing the resource leak. Upgrade is the correct resolution.

**Workaround 1 — Reduce content timeout to free resources faster:**

```
set deviceconfig setting application-content-timeout 3
```

**Workaround 2 — Reduce unknown-tcp session timeout:**

```
set deviceconfig setting application application-default-timeout unknown-tcp 15
```

**Workaround 3 — Application override for high-volume known flows:**

If specific high-volume flows are holding resource slots in the scanning queue, override immediately classifies them and removes them from the queue. Tightly scope to known source/destination/port only. See Section 18.

**Workaround 4 — Temporary scoped policy (internal zones only):**

```
Rule: temp-pan303959-workaround-TICKET-XXXX
Description: PAN-303959 temp workaround — review after upgrade — TICKET-XXXX — Owner: jmiller@adkcyber.com
From Zone:   Trust           ← internal zones only
To Zone:     DMZ, Trust      ← internal zones only — NEVER internet-facing
Source:      <specific-subnets>
Destination: <specific-subnets>
Application: unknown-tcp, unknown-udp
Service:     <specific ports>
Action:      Allow
Profile:     <best-available>
Log:         Session End
Tag:         temporary, pan303959, ticket-XXXX
```

> **Never apply this workaround to internet-facing zones.** The internet-facing path must retain the deny for unknown applications regardless of the bug.

**Workaround 5 — Upgrade (definitive fix):**

```
request system software check
request system software download version <target-version>
```

Test in non-production before deploying to production. Follow your change management process.

---

## 12. Root Cause 5 — Asymmetric Traffic and Non-SYN-TCP

App-ID requires enough session context from both directions. If the firewall sees only one direction, sees traffic after the session is established, or loses flow ownership during HA events, classification degrades to `unknown-tcp` or `non-syn-tcp`.

**Causes:**
- Asymmetric routing (outbound through firewall A, return through firewall B)
- ECMP or PBF sending flows on different paths
- HA failover without session synchronization completing
- Captures taken after session establishment (not from session start)

**Fix:** Correct routing, ECMP/PBF behavior, HA session synchronization, and return-path consistency **before** tuning App-ID or writing signatures. A signature cannot fix a path-visibility problem.

```
# Check HA session synchronization
show high-availability state
show high-availability session-info

# Check routing for a destination
test routing fib-lookup virtual-router default ip <destination-ip>

# Confirm session direction
show session id <session-id>
```

---

## 13. Root Cause 6 — Genuinely Unknown or Anomalous Traffic

Not all `unknown-tcp` is a configuration problem. Some traffic is genuinely unknown:

- **Malware C2:** Custom protocols on non-standard ports specifically to evade App-ID detection
- **Port scanners:** Scan traffic produces `incomplete` and `unknown-tcp` because handshakes never complete
- **Custom scripts and automation:** Raw TCP/UDP without a recognized protocol
- **Misconfigured applications:** Correct TCP but unrecognized application content
- **Encrypted C2 tunneled over common ports:** Binary protocol on TCP/80 or TCP/443 without proper HTTP/TLS structure

### Distinguishing legitimate from anomalous

| Indicator | Legitimate Unknown | Potentially Anomalous |
|-----------|------------------|----------------------|
| Source IP | Known internal host, known application server | Random, rotating, or external source IPs |
| Destination IP | Known internal server, known vendor IP range | TOR exit nodes, dynamic IPs, unexpected external ranges |
| Port | Consistent, documented application port | Ephemeral or uncommon ports |
| Byte volume | Consistent with application behavior | Very small (beacon) or very large (exfiltration) |
| Session frequency | Regular, predictable schedule | Periodic small sessions at regular intervals |
| Time of day | Business hours, application schedule | Off-hours, irregular |
| Send/receive ratio | Roughly balanced | Heavily asymmetric (much more outbound = exfiltration candidate) |

### Response to genuinely anomalous unknown traffic

1. Do **not** add a blanket allow rule — this gives the anomalous source unrestricted TCP access
2. Block the source/destination pair specifically with logging
3. Investigate the source endpoint for compromise
4. If the pattern is consistent with C2 beaconing, follow incident response procedure
5. Submit to WildFire if file-based (WildFire handles unknown application files separately from App-ID)

---

## 14. Policy Logic Traps Involving Unknown Traffic

### 14.1 "I allowed the port — why is it blocked?"

PAN-OS security policy is application-aware. If a rule is restricted to specific applications, the session must match those application objects. A TCP port match alone does not guarantee the session remains allowed after App-ID classification occurs.

| Policy Design | Risk | Safer Design |
|---|---|---|
| Allow tcp/443 service with `application = any` | Allows any application over 443, including evasive or unknown traffic | Use specific applications and `application-default` where possible |
| Allow business app only; deny `unknown-tcp` below it | Initial session may not match business app yet; dependency may be missing | Add explicit dependencies; validate App-ID transition from `ssl`/`web-browsing` to final app |
| Block `unknown-tcp`/`udp` broadly near the top | Can break legitimate internal or newly identified applications | Block by zone/use-case after inventory; use exceptions for known systems |
| Allow `unknown-tcp` from user zones to internet | Creates major exfiltration and evasive protocol exposure | Use temporary narrow allow only for investigation; replace with custom App-ID |

### 14.2 The ssl/web-browsing trap

Many engineers use `ssl` and `web-browsing` as "temporary" allow applications. Newer App-ID signatures or cloud App-IDs can later reclassify the same traffic into a more specific application. If policy allows only `ssl`/`web-browsing` but not the newly identified application, a content update can silently change enforcement and break traffic.

The safer model: allow business applications explicitly with resolved dependencies, and use App-ID Update Safeguard only as a transitional control while policies are updated. [S8]

### 14.3 Application dependencies

Some applications depend on other applications. PAN-OS can implicitly allow certain dependencies, but others must be explicitly added. Commit warnings, Policy Optimizer, and application object details are part of a correct review process. [S6][S7]

| Dependency Type | What It Means | Engineer Action |
|---|---|---|
| Explicit dependency | Firewall shows it as a required dependency | Add the dependency to the rule or create a separate prerequisite rule |
| Implicit dependency | Firewall can automatically allow it only for the dependent app flow | Understand it; do not assume the implicit app is globally allowed |
| Late or indeterminate dependency | Firewall cannot determine dependency early enough | Explicitly allow required parent/base apps or redesign rule order |
| Custom app parent dependency | Custom app is based on `http`, `ssl`, `ms-rpc`, `rtsp`, or another parent | Set parent app when possible so Layer 7 scanning and dependency handling remain available |

---

## 15. Packet Capture Workflow for Unknown Applications

### Capture requirements

- Capture from the **beginning** of the session — not a midstream sample
- Capture **both** directions: client-to-server and server-to-client
- For TCP: include the three-way handshake and early payload
- For UDP: capture multiple complete transactions, not one isolated packet
- Capture **successful** and **failed** examples if possible
- Capture across different application functions: login, browse, upload, sync, call setup, file transfer, heartbeat, logout

```
debug dataplane packet-diag set filter match source <src-ip> destination <dst-ip>
debug dataplane packet-diag set filter on
debug dataplane packet-diag set capture stage receive file unknown_cap
debug dataplane packet-diag set capture stage transmit file unknown_cap_tx
debug dataplane packet-diag set capture on
# wait for a new session
debug dataplane packet-diag set capture off
```

### What to look for in captures

- Stable protocol banner, magic bytes, command names, URI path, host header, SNI, ALPN, user agent, API route, or transaction marker
- Whether the pattern appears early enough for policy enforcement (before content timeout)
- Whether the pattern appears in every session or only after login
- Whether the pattern is unique to the application or could match many unrelated flows
- Whether TLS decryption is required to see the pattern
- Whether UDP payload length, packet direction, or response code can be used safely

> **Signature quality rule:** A custom App-ID signature must be both **stable** (appears consistently in every session) and **unique** (does not identify unrelated applications). If the pattern is only stable or only unique, the signature will either miss traffic or create false positives.

### Testing a capture against App-ID

```
# Run a PCAP through the App-ID engine — invaluable for signature validation
test application-identification pcap <capture-file>
```

This command reports which applications were identified and which signatures matched. Use it before and after writing any custom signature.

---

## 16. The Decision Tree: Unknown → Custom Signature → Application Override

```
UNKNOWN-TCP / UNKNOWN-UDP SESSION IDENTIFIED
              │
              ▼
    Is this 11.2.x (pre-11.2.11 / pre-11.2.7-h10 / pre-11.2.10-h3)?
    ├── YES → Check App-ID resource counters
    │         ├── Exhaustion confirmed → PAN-303959 (Section 11) — upgrade is the fix
    │         └── No exhaustion → continue
    └── NO  → continue
              │
              ▼
    Is traffic one-way / showing non-syn-tcp?
    ├── YES → Fix asymmetric routing / HA (Section 12) before any App-ID work
    └── NO  → continue
              │
              ▼
    Is the traffic encrypted (TLS/SSL)?
    ├── YES → Enable decryption for this traffic
    │         ├── Reveals named app → now a named app policy problem
    │         └── Cannot decrypt (pinned cert, mTLS, compliance)
    │               → Allow as `ssl` on scoped rule; or custom sig from TLS metadata
    └── NO  → continue
              │
              ▼
    Does the App-ID database have a signature?
    ├── YES → Short session / too few packets?
    │         ├── YES → Application override (Section 18) — tightly scoped
    │         └── NO  → Why isn't it matching? Check content update version
    └── NO  → continue
              │
              ▼
    Is this a known internal / proprietary application?
    ├── YES → Packet captures available?
    │         ├── YES → Write custom App-ID signature (Section 17) ← PREFERRED
    │         └── NO  → Application override (Section 18) — temporary while capture gathered
    └── NO  → Known commercial app without a signature?
              ├── YES → Submit to Palo Alto Applipedia for App-ID development
              │         → Temporary: allow on scoped rule with review date
              └── NO  → Anomalous traffic (Section 13)
                        → Block; investigate source endpoint
```

---

## 17. Custom App-ID Signature Lifecycle

### 17.1 When to write a custom signature vs. use application override

| Situation | Custom Signature | Application Override |
|---|---|---|
| Internal application with consistent protocol patterns | **Preferred** | Acceptable temporarily |
| Application with variable/binary protocol, hard to reverse engineer | Difficult | **Preferred** (scoped, documented) |
| Very short sessions (< 3 packets) where signature can't trigger in time | Signature may not fire | **Preferred** |
| Application where threat/URL profile inspection is needed | **Required** — override disables this | Not suitable |
| High-volume flow causing App-ID queue pressure under PAN-303959 | Override reduces queue pressure | **Preferred for this workaround** |
| Vendor application pending official Palo Alto signature | **Preferred** while waiting | Acceptable temporarily |

### 17.2 Recommended lifecycle steps

1. Inventory recurring unknown traffic from ACC and Traffic logs
2. Separate by segment: internet, data center, OT/IoT, VPN, server-to-server, user-to-internet
3. Eliminate scans, resets, health checks, and incomplete-data sessions
4. Identify business-owned recurring flows
5. Capture full sessions for each candidate application
6. If commercial: submit packet captures to Palo Alto Networks for official App-ID development
7. If internal/proprietary: build a custom App-ID signature with parent app where possible
8. Test in a monitor/limited policy scope first
9. Attach the custom app to an explicit security rule with `application-default` or appropriate service
10. Monitor false positives, false negatives, threat logs, ACC, and policy hit counts
11. Remove temporary unknown-tcp allow rules and application overrides after custom App-ID is proven

### 17.3 Custom signature design guidance

| Design Choice | Good Practice | Failure Mode if Wrong |
|---|---|---|
| Parent app | Use a parent (e.g., `web-browsing`, `ssl`) when traffic is truly based on that protocol | No parent can prevent normal threat scanning for that custom app |
| Pattern context | Match in the narrowest correct context: HTTP header, URI path, body, TCP payload, etc. | Wrong context causes no match or expensive/fragile matching |
| Pattern specificity | Use enough specificity to avoid matching other apps | Overbroad signatures relabel unrelated traffic and can create policy bypass |
| Scope | Use transaction scope for request/response functions; session scope for session-level markers | Wrong scope misses multi-transaction behavior or overmatches single transactions |
| Order of conditions | Place most specific conditions first | Broad conditions may match before precise ones |
| Default ports | Define expected ports where known; use None only when protocol-independent matching is required | Incorrect port assumptions cause misses; overly broad port definitions increase false positives |
| Scanning options | Leave scanning enabled where possible | Disabling scanning stops threat engine inspection once the custom app is identified |
| Timeouts | Use custom timeout before application override when the problem is session timeout, not identification | Override may solve timeout but sacrifices Layer 7 visibility unnecessarily |

### 17.4 Signature context options

| Context | Matches In | Use For |
|---------|-----------|---------|
| `unknown-req` | First application payload, client to server | Most application identification — protocol handshake |
| `unknown-rsp` | First application payload, server to client | Server banners, response identification |
| `http-req-headers` | HTTP request headers | HTTP-based protocol identification |
| `http-rsp-headers` | HTTP response headers | HTTP server identification |
| `ssl-cert-subject` | TLS certificate subject | Identify apps from certificate without decryption |
| `ssl-cert-issuer` | TLS certificate issuer | Identify internal CA-signed apps |
| `dns-req-header` | DNS query | DNS-based application identification |
| `packet-payload` | Raw packet payload at offset | Fixed-offset byte patterns in binary protocols |

### 17.5 Creating the custom signature

**Objects → Applications → Add**

```
Name:        internal-app-proto
Description: Internal application management protocol v2 — TICKET-1234 — Review: 2026-11-10
Ports:       tcp/8443
Category:    business-systems
Subcategory: management
Technology:  client-server
Risk:        2

Signatures → Add:
  Name:            detect-banner
  Order Condition: OR

  Condition (text pattern):
    Operator:  Pattern Match
    Context:   unknown-req
    Pattern:   INTERNAL-APP-PROTO
    Qualifier: None

  Condition (binary pattern):
    Operator:  Pattern Match
    Context:   unknown-req
    Pattern:   \x49\x41\x50\x32    (hex magic bytes IAP2)
```

### 17.6 Validation checklist

- [ ] Custom app appears in Traffic logs instead of `unknown-tcp`/`unknown-udp`
- [ ] App matches only the intended source/destination traffic (no false positives)
- [ ] Threat logs still appear when security profiles are attached and test traffic triggers expected inspection
- [ ] Policy hit count increases only on intended rules
- [ ] No unrelated internet or internal flows are relabeled as the custom app
- [ ] Application dependencies are resolved and commit warnings reviewed
- [ ] Content update testing confirms a new Palo Alto App-ID does not get hidden by the custom signature unexpectedly
- [ ] `test application-identification pcap` returns expected classification

### 17.7 Signature lifecycle management

- Add the ticket number and review date to the Description field
- Track against the Palo Alto Applipedia — when Palo Alto releases an official signature, migrate and retire the custom signature
- Document the protocol patterns and how you derived them — the next engineer inheriting this won't have the original captures

---

## 18. Application Override — What It Is, What It Breaks, When to Use It

### 18.1 What application override does

Application override (**Policy → Application Override**) forces sessions matching specified Layer 3/Layer 4 criteria (zone, source, destination, port) to be classified as a specified named application — **bypassing the App-ID engine entirely**. It is fundamentally different from a security rule or custom signature:

- **Security rule:** Controls what is allowed. App-ID still runs.
- **Custom signature:** Teaches App-ID what the application is. App-ID runs and uses the signature.
- **Application override:** Bypasses App-ID entirely. App-ID does not run for these sessions.

Palo Alto guidance recommends avoiding application override when a custom application signature or custom timeout can solve the problem. [S3]

### 18.2 What application override permanently disables

| Area | With Custom App-ID Signature | With Application Override |
|------|------------------------------|--------------------------|
| Named application in logs | Yes — from App-ID signature | Yes — from override (user-defined label) |
| Threat Prevention — full context signatures | Full inspection | **Disabled for context-dependent signatures** |
| Antivirus file inspection | Yes | **Disabled** |
| Anti-Spyware C2 inspection | Yes | **Disabled** |
| Vulnerability Protection | Yes | **Significantly reduced** |
| WildFire file analysis | Yes | **Disabled** |
| URL Filtering | Yes (if decrypted) | **Disabled** |
| Data Filtering / DLP | Yes | **Significantly reduced** |
| App-ID visibility / reporting | Accurate named app | Override label — hides real application behavior |
| Future App-ID updates | Official signatures still apply | New official App-ID never seen for overridden traffic |

> **The critical risk:** Application override tells the firewall "I guarantee this traffic is X application — don't inspect it." If that guarantee is wrong — if malware is tunneling over the same port — it passes without Layer 7 inspection.

### 18.3 Acceptable application override use cases

Application override is appropriate **only** when all of the following are true:

1. You have verified the traffic is legitimate and understand the protocol
2. The session is too short or the protocol too unusual for a custom signature to reliably identify it
3. The content inspection loss is formally accepted and documented
4. Source, destination, and port are tightly scoped
5. A review date and ticket are attached

**Legitimate uses:**
- Load balancer health check traffic (single-packet probes that close immediately)
- High-volume internal monitoring traffic with no reliable Layer 7 pattern
- Legacy internal protocol being decommissioned — not worth a custom signature investment
- Specific decoder or ALG side effects that cannot be remediated another way
- Temporary workaround for PAN-303959 on high-volume known flows (time-limited; internal zones only)

**Never appropriate:**
- Any traffic traversing an internet-facing zone
- Traffic from untrusted or external sources
- Traffic where you're unsure of the protocol content
- As a permanent substitute for anything that can have a custom signature

### 18.4 Governance requirements for every override rule

| Required Field | Reason |
|---|---|
| Business owner | Someone must own the application risk |
| Technical owner | Someone must maintain the object, policy, and evidence |
| Exact source/destination/port scope | Broad overrides create silent visibility gaps |
| Reason for override | Must explain why custom App-ID, official App-ID, decryption, or timeout tuning cannot solve it |
| Lost inspection controls | Documents what security capability is reduced |
| Compensating controls | Restricted zones, known hosts, EDR, log monitoring, vulnerability management |
| Review/expiration date | Prevents permanent emergency exceptions |

### 18.5 Configuring application override correctly

**Policy → Application Override → Add**

Always create a **custom application object** for the override — not an existing App-ID name. This ensures the named application in logs is meaningful, and allows you to later remove the override and write a custom signature without changing your security policy.

```
# Create the custom application object first:
Objects → Applications → Add
  Name:        internal-monitor-app
  Description: Internal load balancer health check — TICKET-5678
  Category:    business-systems

# Then create the override rule:
Policy → Application Override → Add
  Name:        override-lb-health-check-TICKET-5678
  From Zone:   Trust
  To Zone:     DMZ
  Source:      10.10.0.0/24       ← scope tightly
  Destination: <DMZ-server-group> ← scope tightly
  Protocol:    TCP
  Port:        8443
  Application: internal-monitor-app
```

### 18.6 Migrating from application override to custom signature

1. Write and test the custom signature (Section 17)
2. Commit — verify sessions are now identified by the signature in Traffic logs
3. **Disable** (don't delete) the application override rule — leave it disabled 30 days as rollback
4. Add threat profiles to the security rule — content inspection is now available
5. After 30 days with no issues, delete the override rule
6. Document the migration in the change ticket

---

## 19. Policy Design for Unknown Traffic

### 19.1 Recommended rule strategy

- Do not allow `unknown-tcp` or `unknown-udp` broadly from user networks to the internet
- Create explicit deny-and-log rules for unknown internet-bound traffic after known-good application rules, before the final default rule
- For internal networks, separate unknown traffic by zone pair and business function before blocking
- For server-to-server, OT/IoT, or monitoring networks — inventory first; these often contain legitimate proprietary protocols
- Use temporary narrow allow rules only when source, destination, port, owner, and time limit are documented
- Replace temporary unknown allows with custom App-ID or override only after evidence review
- Use `application-default` where possible to prevent applications from running on unexpected ports [S9]

### 19.2 Suggested policy order

| Rule Order | Purpose | Example |
|---|---|---|
| 1 | Known business applications | Allow named applications with dependencies resolved and security profiles attached |
| 2 | Technical prerequisite apps | Allow DNS, NTP, OCSP, CRL, update services, identity services, required infrastructure |
| 3 | Approved custom applications | Allow custom App-ID objects for internal apps with profiles |
| 4 | Temporary investigation exceptions | Narrow source/destination/port allow for unknown traffic with expiration |
| 5 | Unknown deny/log | Deny `unknown-tcp`, `unknown-udp`, and `non-syn-tcp` by zone pair where safe |
| 6 | Default deny/log | Log final deny for all remaining traffic |

### 19.3 Target state architecture

```
# Zone: Trust → Untrust (internet egress)
  All named applications: allowed explicitly with appropriate profiles
  unknown-tcp/udp from Trust to Untrust: DENIED — no exceptions

# Zone: Trust → DMZ (internal access)
  Named applications: allowed explicitly
  unknown-tcp/udp: allowed ONLY for specific source/destination/port
    combinations via override rules with custom application objects
  All other unknown-tcp/udp: DENIED

# Zone: Untrust → any (inbound from internet)
  unknown-tcp/udp: DENIED at all times — no exceptions
  Unknown inbound traffic has no legitimate use case
```

### 19.4 Auditing existing unknown-tcp allow rules

```
# Find all unknown-tcp allow rules
show running security-policy | match unknown-tcp
show running security-policy | match unknown-udp
```

For each rule found:

| Category | Action |
|----------|--------|
| Zero hits | Disable; wait 30 days; delete |
| Active, tightly scoped (specific src/dst/port) | Investigate; classify; migrate to custom signature or override |
| Active, broadly scoped (any source or destination) | Highest priority — classify and remove; this is a security gap |
| Active, internet-facing zones | Immediate priority — unknown inbound/outbound is not acceptable |

### 19.5 Three-phase replacement process for unknown-tcp rules

**Phase 1 — Understand what's hitting the rule:**

```
Monitor → Logs → Traffic
Filter: rule eq <rule-name>
Aggregate: by source IP, destination IP, destination port, bytes
```

Identify distinct traffic patterns — each pattern is a separate classification task.

**Phase 2 — Classify each pattern:**

- Internal proprietary → Custom signature
- External vendor app → Check App-ID database; update content if needed
- Encrypted internal → Enable decryption
- Load balancer health check → Application override (scoped)
- Unknown/suspicious → Block and investigate

**Phase 3 — Replace the rule:**

1. Create specific rules for each classified application
2. Disable (not delete) the `unknown-tcp` rule
3. Monitor for 72 hours — any traffic that was hitting the rule will now be denied and logged
4. After 72 hours with no unexpected denies, delete the rule

---

## 20. Special Cases

### 20.1 Encrypted custom applications

If the payload is encrypted and the firewall cannot decrypt it, a content-based custom signature may be impossible. Alternatives:

- Identify by SNI, certificate metadata, server IP, port, DNS lookup, or EDL
- Use the vendor's published endpoint list (if commercial)
- If those controls are insufficient and the application is trusted — tightly scoped application override as a last resort

### 20.2 Content updates and new App-IDs

Application content updates can introduce new App-IDs or modify existing signatures. A flow previously matching `ssl`, `web-browsing`, or `unknown-tcp` may later match a specific App-ID. This is good for visibility but can break policy if the specific App-ID is not allowed. [S8]

**Response:** Use App-ID Update Safeguard as a transitional control while policies are updated. Monitor traffic logs after every content update for new denies correlated with newly-classified applications.

```
# After a content update — check for new denies
Monitor → Logs → Traffic
Filter: action eq deny AND receive_time geq <content-update-time>
Sort by: application
```

### 20.3 App-ID Cloud Engine

App-ID Cloud Engine can provide more specific IDs for traffic that would otherwise be `ssl` or `web-browsing`. It does not identify private/custom applications and is not a substitute for custom signatures for internal protocols. Treat it as a visibility improvement for eligible cloud applications, not a universal unknown-tcp fix. [S10]

### 20.4 HA and session ownership

In HA active/active configurations, flow ownership affects App-ID classification. If session ownership changes during a failover event and the new owner doesn't have session context from the beginning of the session, classification can degrade. Verify HA2 session synchronization is healthy and session ownership is deterministic before concluding App-ID is the problem.

---

## 21. App-ID and Security Profile Interaction with Unknown Traffic

When traffic is classified as `unknown-tcp` and allowed by a security rule with a threat profile, some inspection still occurs — but it is significantly reduced:

| Profile Feature | Works on unknown-tcp? | Notes |
|---|---|---|
| Antivirus file detection | **Partially** | File-type detection works if magic bytes are visible; application-context rules don't fire |
| Anti-Spyware — DNS sinkhole | Yes | DNS-based detection is protocol-independent |
| Anti-Spyware — C2 signatures | **Reduced** | App-context signatures won't fire; generic TCP pattern signatures may fire |
| Vulnerability Protection | **Reduced** | App-context exploit signatures won't fire; generic exploit pattern signatures may fire |
| WildFire file analysis | **Partially** | Unknown file types submitted based on content detection |
| URL Filtering | **No** | Requires HTTP/HTTPS protocol decoding; unknown-tcp is not decoded |
| Data Filtering / DLP | **Partially** | Pattern-match DLP works; App-ID-dependent DLP profiles don't |

> **The false sense of security:** A rule with `unknown-tcp` allowed and a Strict Threat Prevention profile does **not** provide the same protection as a rule with named applications and a Strict profile. Many vulnerability signatures and context-dependent anti-spyware signatures will not fire on `unknown-tcp`. This is the strongest argument for classifying unknown traffic rather than allowing it with a profile — a custom signature plus a threat profile provides full protection; `unknown-tcp` plus a profile provides only partial protection.

---

## 22. Monitoring and Alerting on Unknown Application Traffic

### 22.1 ACC monitoring

```
ACC → Application tab → filter by Application = unknown-tcp
# Change time range to 7 days to see trend:
# - Sudden spike: PAN-303959, new application, scanner, or malware
# - Gradual growth: new application being deployed
# - Consistent baseline: known unclassified applications
```

### 22.2 Custom report for unknown traffic

**Monitor → Reports → Manage Custom Reports → Add**

```
Report:    unknown-app-weekly-summary
Database:  Traffic Summary
Time:      Last 7 Days
Filter:    (app eq unknown-tcp) or (app eq unknown-udp)
Group By:  Source IP, Destination IP, Destination Port
Sort By:   Sessions (descending)
Scheduled: Weekly email to security team
```

### 22.3 SIEM alerting thresholds

Forward `unknown-tcp`/`unknown-udp` traffic logs to your SIEM and alert on:

- Any `unknown-tcp` session to or from internet zones (should be zero in a mature environment)
- Any `unknown-tcp` session with > 10 MB transferred (potential exfiltration candidate)
- Any source IP generating > 100 `unknown-tcp` sessions per hour (scanner or compromised host)
- Any new source/destination/port tuple generating `unknown-tcp` not seen in prior 30 days (novelty)

### 22.4 Post-content-update monitoring

After every content update, check for reclassification:

```
# Traffic that was unknown-tcp and is now a named app (and possibly denied)
Monitor → Logs → Traffic
Filter: action eq deny AND receive_time geq <content-update-timestamp>
Sort by: application
```

Alert your team after every content update to check for unexpected denies in the 2 hours following installation.

---

## 23. Fix Playbooks

### Playbook 23.1 — Recurring internal application shows unknown-tcp

1. Confirm the flow is legitimate and business-owned (user interview, application owner)
2. Capture full successful sessions from beginning to end — both directions
3. Identify stable, unique payload patterns in Wireshark
4. Create a custom App-ID with appropriate parent app where possible (Section 17)
5. Test with `test application-identification pcap <capture>` before committing to production
6. Attach the custom App-ID to a narrow allow rule with security profiles
7. Monitor for false positives and false negatives over 7 days
8. Remove temporary `unknown-tcp` allow rules after validation
9. Document the protocol, the pattern, the ticket number, and the review date

### Playbook 23.2 — Commercial SaaS application shows unknown-udp

1. Check vendor documentation for required domains, IPs, ports, and protocols
2. Check whether a Palo Alto predefined App-ID exists in the current content release
3. Capture traffic — confirm whether it is truly unknown or only unknown during a short initial phase
4. Submit packet capture to Palo Alto Networks for App-ID development if no predefined signature exists
5. Create a temporary narrow allow based on vendor IP/FQDN objects — not a broad `unknown-udp` allow
6. Set a review date tied to the next content update cycle
7. Update policy when the official App-ID is released

### Playbook 23.3 — Traffic becomes unknown and eventually drops on PAN-OS 11.2.x

1. Check exact PAN-OS version and hotfix against PAN-303959 fix versions (11.2.11 / 11.2.7-h10 / 11.2.10-h3)
2. Collect tech support file, traffic logs, ACC data, session information, and timestamps before clearing sessions or rebooting
3. Confirm App-ID resource counter exhaustion (Section 11)
4. Avoid broad `unknown-tcp` allow rules as the primary fix — the root issue is a resource leak
5. Apply scoped interim workarounds from Section 11 for internal zones only
6. Plan and execute upgrade to a fixed release via your change management process
7. Monitor App-ID resource behavior after upgrade to confirm resolution

### Playbook 23.4 — Custom signature does not match

1. Verify the traffic reaches the firewall and matches the expected security rule
2. Confirm the custom app is committed and visible on the target firewall or device group
3. Run `test application-identification pcap <capture>` — if no match, the signature pattern or context is wrong
4. Check parent app and default port settings
5. Verify the pattern context actually exists in captured traffic (use Wireshark)
6. Confirm traffic is decrypted if the pattern is inside TLS
7. Test with multiple real application actions — not only login or startup
8. Check if another custom App-ID or a Palo Alto signature takes precedence and matches first

### Playbook 23.5 — Application override restored connectivity but security team objects

1. Document exactly what the override matches: source, destination, protocol, port, zone pair
2. Identify which inspection services are reduced or bypassed (Section 18.2)
3. Attempt a custom App-ID signature with parent app and scanning enabled (Section 17)
4. If override remains necessary, restrict to the smallest possible scope
5. Add compensating controls: restricted zones, known host inventory, EDR monitoring, vulnerability management
6. Complete the governance requirements table (Section 18.4) with all required fields
7. Set review date and owner — add to your exceptions register

---

## 24. Operational Guardrails

- Unknown traffic should be actively reduced, not normalized or accepted as background noise
- Never permanently allow `unknown-tcp` or `unknown-udp` broadly from user zones to the internet
- Do not use application override as the first response to every unknown flow
- Prefer official App-ID for commercial applications; custom App-ID for internal applications
- Preserve Layer 7 inspection by using parent applications and leaving scanning enabled
- Treat PAN-303959 as a software-defect path when version and symptoms align — do not paper over it with policy
- Review App-ID dependency warnings during every commit and after every content update
- Use App-ID Update Safeguard as a transition mechanism, not as a reason to ignore policy hygiene
- Keep temporary unknown allows and overrides under expiration control — they belong in an exceptions register
- Report on top unknown applications weekly by source zone, destination zone, destination port, and byte count

---

## 25. Quick Decision Table

| Finding | Most Likely Cause | Recommended Action |
|---------|------------------|-------------------|
| `unknown-tcp` with no payload | Incomplete data, scan, health check, or failed app | Validate source intent; deny/log if unnecessary |
| `unknown-tcp` with stable payload pattern | Internal or unsupported application | Build custom App-ID signature |
| `unknown-udp` sparse traffic | Short-lived UDP or proprietary protocol | Capture multiple transactions; consider custom UDP signature or narrow policy |
| `non-syn-tcp` | Asymmetric routing or midstream session | Fix path symmetry and session ownership |
| Traffic works only with `application = any` | App-ID or dependency mismatch | Resolve dependencies or create custom App-ID |
| Traffic works only with application override | App-ID/decoder/timeout issue or opaque protocol | Replace with custom App-ID if possible; govern override tightly |
| Unknown traffic grows after upgrade and then drops | PAN-303959 candidate on affected 11.2.x | Upgrade to fixed version; collect TAC evidence |
| `ssl`/`web-browsing` allowed but new app blocked after content update | Content update changed App-ID | Use App-ID Update Safeguard during transition; update explicit policy |
| `unknown-tcp` spikes suddenly at a specific time | Scanner, new deployment, malware, or PAN-303959 | Correlate with recent changes; investigate source IPs |
| Override makes it work but threat logs disappear | Application override bypassing Layer 7 | Replace with custom signature; or document with compensating controls |

---

## 26. Known Traps and Exact Fixes

| Trap | Wrong Assumption | Correct Logic | Fix |
|------|-----------------|---------------|-----|
| Application override to fix unknown-tcp | "Override will fix classification and restore normal inspection" | Override bypasses App-ID entirely — most threat profile signatures lose application context | Write a custom signature instead; use override only for sessions too short for signatures |
| Blanket `unknown-tcp` allow rule | "This is temporary until we classify the traffic" | Temporary rules become permanent; this rule becomes the primary uninspected traffic path | Set a review date; classify the traffic; use the 3-phase replacement process (Section 19.5) |
| Allowing `unknown-tcp` with a Strict profile for security | "The profile will still catch threats on unknown traffic" | Many profile signatures require App-ID context; unknown-tcp inspection is significantly reduced | Classify with a custom signature to enable full profile inspection |
| PAN-303959: adding `unknown-tcp` allow rule to internet-facing zone | "The bug is dropping legitimate traffic so I need to allow unknown-tcp everywhere" | Workaround should never apply to internet-facing zones — that creates a permanent security gap | Apply PAN-303959 workaround only to internal zones; internet zones keep the deny |
| Custom signature not matching | "I wrote the signature correctly but sessions still show unknown-tcp" | Pattern may be in wrong context; session may close before trigger; pattern may not be unique | Use `test application-identification pcap` to verify; check context field; check session duration |
| Content update reclassifies unknown-tcp and breaks traffic | "Content updates only add features; they don't break existing flows" | New App-ID signature reclassifies previously-unknown traffic; no rule allows the new app name | Monitor logs after every content update; pre-stage allow rules for new App-ID signatures |
| `incomplete` and `unknown-tcp` treated as the same problem | "They both mean unidentified, so fix them the same way" | `incomplete` = session ended before classification; `unknown-tcp` = classification ran and failed — different causes, different fixes | Diagnose separately; `incomplete` often indicates scanner/health check; not the same as a signature failure |
| Application override on internet-facing traffic | "The port is known and the source is trusted" | External content arrives without Layer 7 content inspection — C2, exfil, and exploits pass uninspected | Never use application override for internet-facing zones; use custom signature or scoped `ssl`/`web-browsing` with profiles |
| Assuming all unknown-tcp is a configuration problem | "If it's unknown, I need to classify it" | Some traffic is genuinely anomalous — malware, scanners, unauthorized tools | Investigate source before classifying; block anomalous traffic rather than classifying it |

---

## 27. CLI and GUI Diagnostic Reference

### 27.1 App-ID diagnostic commands

```
# App-ID engine status
show app-id-engine status

# Active sessions with unknown classification
show session all filter application unknown-tcp
show session all filter application unknown-udp
show session all filter application incomplete

# Inspect a specific session in detail
show session id <session-id>

# App-ID and resource counters (run before + after reproduction)
show counter global filter aspect app-id delta yes
show counter global filter delta yes | match unknown
show counter global filter delta yes | match appid
show counter global filter delta yes | match resource

# Application database search
show application name <app-name>
show application | match <keyword>
show application type custom     ← all custom signatures

# Content version
show system content-version

# Test application identification against a PCAP (invaluable for signature validation)
test application-identification pcap <filename>

# Application override policy
show running application-override-policy

# App-ID cache
show app-id-cache

# Check for pending content updates
request system content upgrade check
show content-updates

# App-ID engine full stats (use during maintenance window)
debug app-id engine stats
```

### 27.2 Session and traffic investigation

```
# Find unknown sessions by source
show session all filter source <ip> application unknown-tcp

# Packet capture for an unknown session (all four stages)
debug dataplane packet-diag set filter match source <src-ip> destination <dst-ip>
debug dataplane packet-diag set filter on
debug dataplane packet-diag set capture stage receive file unknown_cap
debug dataplane packet-diag set capture stage transmit file unknown_cap_tx
debug dataplane packet-diag set capture stage drop file unknown_drop
debug dataplane packet-diag set capture on
# wait for session
debug dataplane packet-diag set capture off
debug dataplane packet-diag clear filter-marked-session all
# retrieve from /var/tmp/ via SCP

# Check current application content timeout
show running application-content-timeout

# Dataplane resource utilization (relevant to PAN-303959)
show running resource-monitor
show system resources
```

### 27.3 GUI diagnostic path

```
Monitor → Logs → Traffic
  Filter: app eq unknown-tcp
  Columns: Source, Destination, Destination Port, From Zone, To Zone,
           Application, Rule, Action, Bytes, Packets, Session Duration

ACC → Application tab
  Filter by Application: unknown-tcp, unknown-udp
  View: Top Sources, Top Destinations, Trend over time

Objects → Applications
  Filter: Type = Custom              ← all custom signatures
  Select app → Depends On tab        ← dependencies
  Select app → Signature tab         ← signature patterns

Policies → Application Override
  Review all override rules: source, destination, port scope, description, tag, review date

Policies → Security → Policy Optimizer
  Rules with no app specified
  Rules with no recent hits
  Rules using unknown-tcp or unknown-udp
```

---

## 28. Change-Control Checklist

| Check | Question | Pass Condition |
|-------|----------|----------------|
| Root cause identified | Is the specific root cause confirmed with evidence? | Root cause documented (packet capture, counter output, version confirmation) |
| PAN-303959 scope | If on 11.2.x, have resource counters been checked? | Counter output reviewed; PAN-303959 confirmed or excluded |
| Solution selection | Is the solution (custom sig vs. override vs. scoped allow) appropriate for the zone and traffic type? | Internet-facing: never override or blanket allow. Internal: prefer custom signature |
| Custom signature test | Was it tested with `test application-identification pcap`? | PCAP test confirms correct identification |
| Override scope | If application override is used, is it scoped to the narrowest possible source/destination/port? | No broad ranges; specific addresses where possible |
| Override documentation | Is the security impact documented and formally approved? | Governance requirements table (Section 18.4) completed |
| Temporary rule controls | If a temporary `unknown-tcp` allow rule was added, does it have a review date, owner, and ticket? | Description field contains all three |
| Profile attached | If unknown-tcp or unknown-udp is allowed, is the best-available threat profile attached? | Profile assigned; reduced inspection acknowledged |
| Content update monitoring | Is there a plan to check logs after the next content update? | Log filter prepared; team notified |
| Rollback plan | Is there a rollback procedure if the change causes unexpected denies? | Config snapshot taken; override rules disabled rather than deleted for 30 days |

---

## 29. Escalation Bundle

Escalate to senior firewall engineering or Palo Alto TAC with complete evidence. "Unknown" is not enough information to determine cause.

| Evidence Item | Why It Matters |
|---|---|
| PAN-OS version and content release | Determines if PAN-303959 or content-update behavior is plausible |
| Traffic log export | Shows application, rule, action, session end reason, bytes, and timing |
| Packet capture from session start | Shows whether payload exists and whether a signature can be built |
| `show session id` output | Confirms NAT, zones, policy, timeout, app state, and flow direction |
| Rulebase snippet | Shows whether policy denies unknown or misses dependencies |
| Panorama device group/template info | Confirms local vs. pushed objects and hierarchy mismatch |
| Custom App-ID XML/object screenshots | Needed if custom signature behavior is suspected |
| Application override rules | Needed to understand Layer 7 bypass scope |
| App-ID resource counter output | Needed for PAN-303959 diagnosis |
| Tech support file | Required for resource leaks, counters, or software defect analysis |

**CLI output checklist for escalation:**

- [ ] `show system info | match version`
- [ ] `show system content-version`
- [ ] `show counter global filter aspect app-id delta yes`
- [ ] `show session id <id>` for a representative failing session
- [ ] `show app-id-engine status`
- [ ] `test application-identification pcap <capture>` if a custom signature is being tested
- [ ] Tech support file: **Device → Support → Generate Tech Support File**
- [ ] Traffic log export: source, destination, port, application, time, byte volume

---

## 30. PCNSE-Style Quick Answer Key

| Question Pattern | Correct Answer |
|---|---|
| What does `unknown-tcp` mean? | App-ID ran its full classification process for a TCP session and did not match any known application signature |
| What does `incomplete` mean vs. `unknown-tcp`? | `incomplete` = session ended before App-ID could classify. `unknown-tcp` = classification ran to completion and failed. Different causes, different fixes |
| An internal app shows `unknown-tcp` on port 443 with TLS. First thing to check? | Whether SSL decryption is enabled. Without decryption, App-ID cannot see the payload to identify the application |
| What does application override do to threat inspection? | It bypasses App-ID entirely. Most threat profile signatures that rely on application context will not fire. Content inspection is severely reduced |
| When is application override appropriate? | For tightly scoped known traffic where sessions are too short for signature-based classification; content inspection loss is formally accepted and documented; never for internet-facing traffic |
| Custom App-ID signature written but sessions still show unknown-tcp. First check? | Run `test application-identification pcap` to verify the signature matches. Check whether the pattern context matches where the pattern actually appears in the payload |
| PAN-303959 causes unknown-tcp. What is the correct fix? | Upgrade to PAN-OS 11.2.11, 11.2.7-h10, or 11.2.10-h3. Interim workarounds (content timeout reduction, scoped override) address symptoms only — the resource leak requires a software fix |
| Content update installed; previously-working traffic now denied with a new app name. Why? | The content update added an App-ID signature that reclassified the traffic from unknown-tcp to a named application. No security rule allows the new name, so interzone-default denies it |
| Why can't you just allow `unknown-tcp` with a Strict profile to make it safe? | Many Threat Prevention signatures require application context. A Strict profile on `unknown-tcp` provides significantly less coverage than the same profile on a named application |
| What command tests a custom App-ID signature against a packet capture? | `test application-identification pcap <filename>` |
| What is the difference between a custom App-ID signature and an application override? | Custom signature teaches App-ID to identify the application — App-ID engine runs and profile inspection is full. Application override bypasses App-ID — engine does not run; Layer 7 inspection is severely reduced |

---

## 31. References

| ID | Reference | URL | Used For |
|----|-----------|-----|----------|
| S1 | Palo Alto Networks: PAN-OS 11.2.11 Addressed Issues — PAN-303959 | https://docs.paloaltonetworks.com/pan-os/11-2/pan-os-release-notes/pan-os-11-2-11-known-and-addressed-issues/pan-os-11-2-11-addressed-issues | PAN-303959 fix confirmation and version specifics |
| S2 | Palo Alto Networks: PAN-OS 11.2.9 Known Issues — PAN-303959 | https://docs.paloaltonetworks.com/pan-os/11-2/pan-os-release-notes/pan-os-11-2-9-known-and-addressed-issues/pan-os-11-2-9-known-issues | PAN-303959 description and affected behavior |
| S3 | Palo Alto Networks: Manage Custom or Unknown Applications | https://docs.paloaltonetworks.com/ngfw/administration/app-id/manage-custom-or-unknown-applications | Unknown classifications, custom App-ID recommendations, override guidance |
| S4 | Palo Alto Networks: About Custom Application and Threat Signatures | https://docs.paloaltonetworks.com/advanced-threat-prevention/custom-signatures/custom-application-and-threat-signatures/about-custom-application-signatures | Custom signatures, unknown traffic, custom app precedence |
| S5 | Palo Alto Networks: Create a Custom Application Signature | https://docs.paloaltonetworks.com/advanced-threat-prevention/custom-signatures/custom-application-and-threat-signatures/create-a-custom-application-signature | Pattern identification, scope, context, and validation workflow |
| S6 | Palo Alto Networks: Resolve Application Dependencies | https://docs.paloaltonetworks.com/ngfw/administration/app-id/use-application-objects-in-policy/resolve-application-dependencies | Explicit and implicit dependency resolution |
| S7 | Palo Alto Networks: Applications with Implicit Support | https://docs.paloaltonetworks.com/ngfw/administration/app-id/applications-with-implicit-support | Explicit vs. implicit application dependencies |
| S8 | Palo Alto Networks: App-ID Update Safeguard | https://docs.paloaltonetworks.com/ngfw/administration/app-id/app-id-update-safeguard | Transitional protection for new and modified App-IDs after content updates |
| S9 | Palo Alto Networks: Safely Enable Applications on Default Ports | https://docs.paloaltonetworks.com/ngfw/administration/app-id/application-default | application-default service field behavior |
| S10 | Palo Alto Networks: App-ID Cloud Engine | https://docs.paloaltonetworks.com/ngfw/administration/app-id/cloud-based-app-id-service | App-ID Cloud Engine scope and limitations |
| — | Palo Alto Networks: Applipedia | https://applipedia.paloaltonetworks.com | Searching existing App-ID signatures |
| — | Palo Alto Networks: Traffic Log Fields | https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields | Log field definitions |
| — | Palo Alto Networks: Policy Optimizer | https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/security-policy/policy-optimizer | Identifying unknown-app rules and App-ID optimization |

---

## 32. Revision History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-05-10 | Original — engineering KB (MD): App-ID lifecycle, 6 root causes, PAN-303959 workarounds, custom signature authoring, override tradeoffs, unknown-tcp rule lifecycle, profile interaction, SIEM alerting, PCNSE Q&A |
| 1.1 | 2026-05-10 | Original — formal KB (DOCX): first-principles model, definitions table, PAN-303959 fix versions (11.2.11/11.2.7-h10/11.2.10-h3), policy logic traps, packet capture requirements, custom App-ID design guidance table, override governance requirements, policy rule strategy table, special cases, fix playbooks, operational guardrails, quick decision table, 10 cited official sources |
| 2.0 | 2026-05-10 | Merged — consolidated both sources; added PAN-303959 exact fix version table, classification hierarchy with timing, definitions table, App-ID Cloud Engine section, App-ID Update Safeguard concept, explicit/implicit dependency types table, signature quality rule callout, `test application-identification pcap` command, signature context options table, override feature breakdown table, governance requirements table, 3-phase rule replacement process, SIEM alerting thresholds, post-content-update monitoring, 5 fix playbooks, operational guardrails, quick decision table, full CLI cheat sheet, 10 cited references with URLs |

> **Maintenance recommendation:** Review this KB after major PAN-OS upgrades, App-ID content policy changes, and TAC advisories related to App-ID, Content-ID, or dataplane resource behavior. Validate all behavior against the firewall software version and content release in use.

*End of Article KB-PAN-APPID-001*
