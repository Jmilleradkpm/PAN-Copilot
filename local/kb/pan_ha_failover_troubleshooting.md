# KB: HA Failover, Stuck-in-Initial-State, and HA Link Design on Palo Alto Networks NGFW

**Article ID:** KB-PAN-HA-001
**Revision:** 2.0 — Consolidated

| Field | Value |
|-------|-------|
| **Article Owner** | Network Security Engineering |
| **Primary Platform** | Palo Alto Networks NGFW / PAN-OS / Panorama |
| **Applies To** | PAN-OS 10.0 / 10.1 / 10.2 / 11.0 / 11.1 / 11.2; Active/Passive and Active/Active HA; PA-3200, PA-3400, PA-5200, PA-5400, PA-7000, PA-7500 series; VM-Series HA |
| **Audience** | Firewall engineers, NOC/SOC analysts, MSP escalation teams, infrastructure owners, PCNSE candidates |
| **Severity** | P1 (split-brain / both peers non-forwarding), P2 (stuck in initial / no standby), P3 (flapping / intermittent) |
| **Operational Risk** | Incorrect remediation can create traffic outage, split-brain, session loss, or configuration divergence |
| **Last Reviewed** | May 10, 2026 |

> **Engineer summary:** "HA is up" does not mean "HA works." The HA state machine has six distinct states. `Initial` is where sessions are synchronized from the active peer before a firewall can transition to ready. A firewall stuck in `initial` cannot forward traffic and cannot become active. The causes range from plugin version mismatch (most common post-upgrade trap) to HA2 link timing problems, session synchronization resource exhaustion, and split-brain after an unclean upgrade. Each cause has a specific diagnostic signature and fix — none of them are "reboot and hope."

> **Operational principle:** Do not treat `initial` as a cosmetic state. The firewall is withholding normal HA participation because one or more safety assumptions have not been proven. A peer that remains in `initial` is evidence that HA negotiation or synchronization is incomplete — not that everything is fine but a little slow.

> **Core rule:** Never perform a PAN-OS upgrade on an HA pair without verifying plugin version parity, HA link health on both peers, and a known-good rollback path. Most stuck-in-initial and split-brain incidents are preventable with a ten-minute pre-upgrade checklist.

---

## Contents

1. Problem Statement and Scope
2. First-Principles Model of HA Failure
3. HA State Machine — All Six States
4. HA Link Architecture — HA1, HA2, HA3, HSCI
5. Root-Cause Matrix
6. Incident Triage Workflow
7. Root Cause 1 — Plugin Version Mismatch
8. Root Cause 2 — HA2 Link Timing on Upgrade
9. Root Cause 3 — Session Synchronization Resource Exhaustion
10. Root Cause 4 — Split-Brain After Upgrade or HA1 Failure
11. Root Cause 5 — Path Monitoring Misconfiguration
12. Root Cause 6 — HA1 Link Failure or Flapping
13. Root Cause 7 — HSCI / HA3 Link Issues on Chassis Platforms
14. Root Cause 8 — Priority / Preemption Misconfiguration
15. Root Cause 9 — PAN-OS, Content, License, or Feature Mismatch
16. Active/Active-Specific HA Issues
17. Platform-Specific HA Link Design
18. Path Monitoring — Design and Tuning
19. Recovery Runbooks
20. Upgrade Runbook for HA Pairs
21. Post-Failover Validation and Final Resolution Criteria
22. Preventive Design Checklist
23. Known Traps and Exact Fixes
24. CLI and GUI Diagnostic Reference
25. Change-Control Checklist
26. Escalation Bundle
27. PCNSE-Style Quick Answer Key
28. References
29. Revision History

---

## 1. Problem Statement and Scope

High Availability on Palo Alto Networks NGFWs is a complex state machine that coordinates two or more firewalls into a logical unit. When it works correctly, traffic fails over in seconds and users notice nothing. When it fails, the outcomes range from brief service interruption to complete dual-failure — both firewalls in a non-forwarding state simultaneously — which is operationally worse than having no HA at all.

The most common escalated HA failures are:

**Stuck in initial state** — a firewall that has been in the `initial` state for minutes or longer after a failover or reboot. The firewall is not forwarding traffic and cannot move to `active` or `passive`. `Initial` is expected to be transient. If the firewall remains there, HA discovery, negotiation, control-plane communication, runtime state synchronization, or feature compatibility is not completing.

**HA2 timing on upgrade** — after a PAN-OS upgrade, the HA2 link (session synchronization) takes longer to re-establish than HA1 (control link). The firewall attempts to synchronize sessions before HA2 is ready, fails, and gets stuck.

**Plugin mismatch** — plugin version differences between HA peers prevent session synchronization from proceeding. The most common post-upgrade trap.

**Split-brain** — both firewalls simultaneously believe they are active. Both send traffic, and upstream/downstream devices see conflicting MAC addresses or routing states. The highest-severity HA failure mode.

**Path monitoring triggers false failover** — path monitoring is misconfigured to monitor targets only reachable through the active firewall, causing cascade failover loops.

**HSCI / HA3 issues on chassis platforms** — PA-7000, PA-7500, and PA-5400 series have specific cabling, transceiver, and configuration requirements that differ from standard deployments.

**Scope:** Active/Passive HA, Active/Active HA, Panorama-managed HA pairs, PA-3200, PA-3400, PA-5200, PA-5400, PA-7000, PA-7500 platforms, and VM-Series HA deployments.

---

## 2. First-Principles Model of HA Failure

HA can only operate safely if both firewalls can prove the following conditions simultaneously:

1. **They are the correct HA peers:** same HA group, compatible mode, and matching critical HA configuration
2. **They can communicate over the control plane:** HA1 must exchange heartbeats, hello messages, election data, and configuration synchronization data
3. **They can synchronize runtime state:** HA2 must synchronize sessions and forwarding state if session synchronization is enabled
4. **Their software, plugins, features, and runtime capabilities are compatible:** PAN-OS version, content versions, enabled features, plugins, virtual systems, VPN capability, GTP/SCTP settings, and other feature flags must not create an HA mismatch

If any of these conditions fails, the firewall may not safely transition to `passive`, `active`, `active-primary`, or `active-secondary`. A peer that remains in `initial` is evidence that HA negotiation or synchronization is incomplete on at least one of these four conditions.

The diagnostic job is to determine which of the four conditions is failing — not to guess, and not to reboot before collecting evidence.

---

## 3. HA State Machine — All Six States

Understanding the state machine is the prerequisite for diagnosing any HA problem. A firewall in any state other than `active` or `passive` (or `active-primary`/`active-secondary` in A/A) is not forwarding traffic as designed.

### The six states

| State | Meaning | Normal Duration | Stuck If... |
|-------|---------|-----------------|-------------|
| `initial` | Firewall is synchronizing session state from the active peer before it can forward. Also seen as: `Initial - Waiting for state synchronization completion` | 30–60 seconds on a lightly loaded system; longer on busy systems | > 5 minutes without transitioning — plugin mismatch, HA2 link not up, or feature incompatibility |
| `passive` | Firewall is standby; monitoring HA; ready to take over | Indefinite — this is normal | N/A |
| `active` | Firewall is forwarding traffic; owns floating IPs; elected primary | Indefinite — this is normal | N/A unless BOTH peers show `active` — that is split-brain |
| `suspended` | Firewall has been administratively suspended from HA | Until manually resumed | > expected maintenance window → investigate who suspended it and why |
| `non-functional` | Firewall failed its own health check or detected a configuration/capability mismatch; cannot participate | Until health condition resolved | Persistent → investigate hardware, software, license, or feature mismatch |
| `tentative` | Active/Active only — peer is re-learning session state after a link recovery | Seconds | > 60 seconds in A/A → investigate HA2 or session sync collision |

### Observed state interpretation

| Peer 1 State | Peer 2 State | Situation | Severity | Immediate Focus |
|---|---|---|---|---|
| `active` | `passive` | Normal | — | None |
| `active` | `initial` | Passive stuck in initial | P2 | Check HA1, HA2, plugin/feature compatibility, state-sync status |
| `active` | `initial` (waiting for sync) | HA2 / session sync not completing | P2 | Check HA2 link, HA2 keep-alive, session sync, HA2 transport |
| `active` | `non-functional` | Feature/capability mismatch or peer health failure | P2 | Check system logs, feature mismatch, dataplane status, HA compatibility |
| `active` | `suspended` | Peer suspended | P2 | Determine why; restore only after HA1 confirmed stable |
| `active` | `active` | **Split-brain** | **P1** | Suspend the wrong peer immediately; restore HA1 before returning to functional |
| `initial` | `initial` | Dual-initial collision | P1 | Disable session sync on both; restart HA in correct sequence |
| `initial` | `passive` | Active re-syncing / no active | P2 | Investigate which peer should be active |
| Both `non-functional` | Both `non-functional` | Mutual incompatibility | P1 | Collect logs; do not reboot before evidence collected |

### The transition that matters most: `initial` → `passive`

When a firewall boots or recovers, it enters `initial` and begins pulling session state from the active peer over HA2. When synchronization completes, it transitions to `passive`. If synchronization fails, stalls, or HA2 is unavailable, the firewall stays in `initial` indefinitely.

**`initial` is silent failure.** HA links may show green. The GUI may look normal. But the firewall cannot become active and cannot forward traffic. Always check both peers explicitly.

```
# Check both peers — this is the first command for every HA ticket
show high-availability state
show high-availability all
show high-availability transitions
```

---

## 4. HA Link Architecture — HA1, HA2, HA3, HSCI

Every HA failure eventually traces back to one of these links. Understanding what each carries and what fails when it goes down is the foundation for all HA diagnostics.

### HA1 — Control link

| Property | Value |
|----------|-------|
| **Carries** | Hello keepalives, state synchronization messages, HA election, configuration sync, peer status, heartbeat |
| **Failure consequence** | Both peers believe the other is dead → split-brain risk |
| **Encryption** | Optional (AES-256); required when HA1 traverses untrusted segments |
| **Backup** | HA1-backup — strongly recommended on a different physical interface and switch |
| **Heartbeat backup** | Enable where appropriate; provides an additional keepalive path independent of HA1 |
| **Default ports** | TCP/28769, TCP/28260 |
| **Platform note** | HA1-B (backup) may have a dependency on dataplane restart on some platforms — verify in platform-specific documentation |

### HA2 — Session synchronization link

| Property | Value |
|----------|-------|
| **Carries** | Session table, forwarding table, ARP table, IPsec SA synchronization, NAT translation table |
| **Failure consequence** | Passive peer has no session state; failover drops all existing sessions |
| **Encryption** | Optional AES-256; adds CPU overhead |
| **Backup** | HA2-backup — recommended for production; must be on a different interface from HA2 |
| **Protocol** | Layer 2 Ethernet (default); IP-based for non-adjacent peers |
| **Default port** | UDP/28769 (Layer 2 mode); varies in IP mode |
| **Keep-alive** | Must be enabled and tuned; without it, HA2 path failure may not be detected deterministically |

### HA3 — Active/Active packet forwarding link

| Property | Value |
|----------|-------|
| **Carries** | Asymmetric packets forwarded between A/A peers; not used in A/P |
| **Failure consequence** | Asymmetric sessions cannot be forwarded between peers → drops |
| **Speed requirement** | Must equal or exceed peak asymmetric forwarding throughput between peers |
| **Layer** | Layer 2 HA forwarding — not normal routed traffic; do not route HA3 through Layer 3 infrastructure |
| **MTU** | Requires sufficient MTU to accommodate the HA3 encapsulation header; jumbo frames may be required |

### HSCI — High Speed Chassis Interconnect (PA-5400, PA-7000, PA-7500)

| Property | Value |
|----------|-------|
| **Replaces** | HA1, HA2, and HA3 on chassis platforms — not a normal Ethernet path |
| **Physical** | Dedicated HSCI ports on chassis (QSFP+ on PA-7000; SFP28 on PA-5400) |
| **Connection** | HSCI-A connects directly to HSCI-A on the peer — where documentation requires direct connection, connect directly |
| **Cable** | DAC for short runs; AOC for longer runs — must be on the Palo Alto compatibility matrix |
| **Failure consequence** | Complete HA communication loss if both HSCI links fail |
| **Warning** | Do not mix HSCI and dataplane interfaces for HA2/HA2-backup on platforms where that combination is unsupported — causes commit failure or unstable HA behavior |

### HA link health check

```
show high-availability link-monitoring
show high-availability path-monitoring
show high-availability state
show high-availability interface ha2
show interface ha1
show interface ha2
show interface ha1-backup
show interface ha2-backup
```

---

## 5. Root-Cause Matrix

| Symptom | Likely Cause | What to Verify | Fix |
|---|---|---|---|
| Stuck in `initial` after upgrade — most common | Plugin version mismatch between peers | `show plugins installed` on both peers | Match plugin versions; temporarily disable session sync while upgrading |
| Stuck in `initial - waiting for state synchronization` | HA2 link not up or too slow post-upgrade | `show high-availability interface ha2`; HA2 link timing | Toggle session sync after HA2 is confirmed up |
| `non-functional` state | PAN-OS, content, license, or feature capability mismatch | `show system info`; `show plugins installed`; `request license info` | Align all mismatched items between peers |
| Both firewalls show `active` | Split-brain — HA1 failure or peers lost sight of each other | HA1 and HA1-backup link states; logs around the event | Suspend wrong peer; restore HA1; return to functional only after HA1 stable |
| `suspended` unexpectedly | Administrative suspend not cleared; automation ran `request ha state suspend` | `show high-availability state`; audit logs | `request ha state functional` after investigating why |
| Failover occurs but all sessions drop | HA2 was down or session sync was disabled; passive had no session table | HA2 link history; session sync status | Fix HA2; re-enable sync; validate with controlled failover test |
| Repeated failover / HA flapping | Path monitoring target unreachable on both peers alternately | Path monitoring config and target reachability | Fix targets; tune timers; set Failure Condition = All |
| Spurious failover from path monitoring | Targets only reachable through the active firewall | Path monitoring target list; return path reachability | Replace with infrastructure IPs reachable via physical network |
| HA2 path failure not detected | HA2 keep-alive not enabled or poorly tuned | HA2 keep-alive config on both peers | Enable and tune HA2 keep-alive threshold |
| Upgrade: peer never rejoins HA | Wrong upgrade sequence; both peers upgraded simultaneously; plugins diverged | Upgrade sequence log; plugin versions post-upgrade | Follow passive-first upgrade sequence; verify plugin parity at each phase |
| HSCI link not initializing | Wrong cable type; transceiver not on compatibility matrix; port misconfigured | HSCI port status; cable/transceiver vs. compatibility matrix | Replace with supported cable; verify HSCI config per platform guide |
| Preemption triggers repeated failover | Preemption enabled with default short hold time; active recovers and preempts before sessions sync | Preemption config; preemption hold time | Extend hold time to 30–60 seconds or disable preemption during maintenance |
| A/A sessions not forwarded between peers | HA3 link down, undersized, or misconfigured; packet forwarding not enabled | HA3 link state; A/A packet forwarding config | Fix HA3; enable packet forwarding; verify session owner logic |
| `tentative` state persists in A/A | HA3 instability or session sync collision | HA3 link state; session sync counters | Suspend tentative peer; wait; return to functional |

---

## 6. Incident Triage Workflow

### Minimum data to collect before making any change

The system log and HA state on both peers at the moment of the incident may be overwritten if you reboot or clear sessions. Collect everything before touching any configuration.

- [ ] HA state on both peers: `show high-availability state` and `show high-availability all`
- [ ] HA transitions: `show high-availability transitions` on both peers
- [ ] System logs around the event: `show log system direction equal backward`
- [ ] HA link states: `show high-availability interface ha2`; `show interface ha1`; `show interface ha2`
- [ ] Plugin versions on both peers: `show plugins installed`
- [ ] PAN-OS version: `show system info | match version`
- [ ] Session sync status: `show high-availability state-synchronization`
- [ ] Path monitoring status: `show high-availability all` (includes path monitoring section)
- [ ] Jobs in progress: `show jobs all`
- [ ] License status: `request license info`
- [ ] Whether a recent upgrade, commit, plugin update, or Panorama push preceded the event

### Step 1 — Determine the actual HA state of both peers

```
show high-availability state
show high-availability transitions
```

Reference the state pair table in Section 3. The state pair tells you the incident category and severity before any other investigation.

### Step 2 — Check for plugin mismatch

```
# Run on both peers — compare every line
show plugins installed
```

Any difference in plugin name, version, or status is a candidate root cause for stuck-in-initial. Go to Section 7 immediately if mismatch exists.

### Step 3 — Check HA2 and session sync status

```
show high-availability interface ha2
show high-availability state-synchronization
show high-availability link-monitoring
```

If HA2 is `down` or was recently `down` around the time the problem started — go to Section 8.

### Step 4 — Check system and HA agent logs

```
# System log HA entries
show log system direction equal backward | match ha
show log system direction equal backward | match failover
show log system direction equal backward | match plugin
show log system direction equal backward | match suspend
show log system direction equal backward | match election

# HA agent and management plane logs (for deep diagnosis)
less mp-log ha_agent.log
tail follow yes mp-log ha_agent.log
less mp-log configd.log
less mp-log ms.log
```

The system log almost always contains an entry explaining why the state transition occurred. The HA agent log provides deeper protocol-level detail for TAC escalation.

### Step 5 — Feature and software compatibility check

```
show system info
show plugins installed
request license info
show high-availability all
```

Check for differences in PAN-OS version, content versions, multi-VSYS capability, GTP/SCTP/VPN features, FIPS or CC mode, and license state between peers. Any mismatch is a candidate cause for `non-functional` or stuck-in-initial. See Section 15.

### Step 6 — Split-brain immediate response

If both firewalls show `active`:

1. **Do not reboot either firewall.** Rebooting the wrong peer takes down the network.
2. Identify which peer is passing traffic: check session counts, traffic logs, upstream switch MAC tables.
3. Suspend the peer that is NOT the correct active:
   ```
   request high-availability state suspend
   ```
4. Verify the intended active peer is now sole active.
5. Restore HA1 and HA1-backup connectivity. Verify stability before the next step.
6. Return the suspended peer to functional only after HA1 is confirmed stable:
   ```
   request high-availability state functional
   ```
7. Collect root-cause evidence before the next maintenance window.

### Step 7 — Stuck-in-initial immediate stabilization

If a firewall has been in `initial` for > 5 minutes:

```
# Option 1 — Toggle session sync to break the deadlock (resolves most post-upgrade cases)
# On the ACTIVE peer:
# GUI: Device → High Availability → HA Communications → HA2 → uncheck Session Synchronization
# Commit on both peers
# Wait 30 seconds — confirm stuck peer transitions to passive
# Re-enable session synchronization
# Commit on both peers
# Verify sync resumes: show high-availability state-synchronization

# Option 2 — If session sync toggle doesn't resolve:
# On the stuck peer only:
request high-availability state suspend
# Wait 10 seconds
request high-availability state functional
```

> **Risk of workaround:** Disabling session synchronization means existing sessions will not survive a failover while sync is disabled. Re-enable it and verify sync completion before considering the issue closed.

---

## 7. Root Cause 1 — Plugin Version Mismatch

### Why this happens

Plugins (GlobalProtect, Cloud Services, Advanced Threat Prevention, SD-WAN, telemetry, AIOps) have their own version numbers independent of PAN-OS. During a PAN-OS upgrade on one peer, the new version may install or require a different plugin version than the peer still running the old version. The HA state machine performs a compatibility check during the `initial` synchronization phase. Plugin mismatch prevents session sync from proceeding.

**High-risk plugin timing scenarios:**
- PAN-OS upgrade performed close to a plugin upgrade
- Panorama plugin upgrade applied before both HA peers are aligned
- VM-Series plugin version differs between peers
- SD-WAN, cloud, telemetry, or AIOps plugin changed on only one peer
- Replacement firewall introduced with a different plugin set
- Failed plugin install or uninstall left one peer in a different state

### Detection

```
# Run on BOTH peers — compare every line
show plugins installed

# Check available updates
request plugins check

# System log on the stuck peer will typically show:
# "HA peer has incompatible version of plugin <plugin-name>"
# "Session synchronization suspended due to peer incompatibility"
show log system direction equal backward | match plugin
```

### Fix

**Step 1 — Identify the mismatch:**

```
show plugins installed   # on both peers
```

Both peers must run identical plugin names, versions, and states.

**Step 2 — While waiting for plugin alignment — temporarily disable session sync:**

Disabling session sync allows the firewall to transition from `initial` to `passive` without completing full session synchronization. This restores standby capability while the plugin upgrade proceeds.

```
# GUI: Device → High Availability → HA Communications → HA2 → uncheck Enable Session Synchronization
# Commit on both peers
# Verify: show high-availability state   (stuck peer should now show passive)
```

**Step 3 — Align plugin versions:**

```
# Download and install matching plugin version on the lagging peer
request plugins check
request plugins download <plugin-name> version <version>
request plugins install <plugin-name> version <version>
# Reboot only if required by plugin documentation or TAC guidance
```

If a plugin is not required on either peer, uninstall it from both rather than adding it.

**Step 4 — Re-enable session sync and verify:**

```
# GUI: Device → High Availability → HA Communications → HA2 → check Enable Session Synchronization
# Commit on both peers
show high-availability state-synchronization   # confirm sync resumes
show high-availability state                   # confirm expected active/passive state
```

### Prevention

- Always verify plugin version parity before beginning any PAN-OS upgrade on an HA pair
- Do not introduce plugin changes in the same maintenance window as a PAN-OS upgrade unless required
- Confirm Panorama is not pushing different plugin configuration to each peer independently
- After completing a PAN-OS upgrade on both peers, verify plugins match before re-enabling session sync

---

## 8. Root Cause 2 — HA2 Link Timing on Upgrade

### Why this happens

After a PAN-OS upgrade and reboot, HA1 (management plane, initializes early) typically comes up before HA2 (dataplane, requires NPU/dataplane full initialization). The timing gap is 30–90 seconds but can be longer on large session tables, high-throughput platforms, or multi-NPU systems.

During this window:
1. HA1 is up; the active peer detects the recovering peer and initiates session sync
2. The recovering peer cannot receive sync data — HA2 is not yet up
3. Session sync attempt times out
4. The recovering peer stays in `initial` because sync never completed

This is a race condition, not a misconfiguration. It is reproducible after every upgrade reboot on some platform/configuration combinations.

### Detection

```
# Check HA2 link state
show high-availability interface ha2

# Check when HA2 came up relative to HA1
show log system direction equal backward | match ha2
show log system direction equal backward | match ha1

# Check session sync state
show high-availability state-synchronization

# Check link monitoring
show high-availability link-monitoring
```

### Fix — immediate

```
# Step 1: Confirm HA2 is now up
show high-availability interface ha2

# Step 2: Toggle session sync to force a fresh sync attempt
# On the ACTIVE peer:
# Disable session sync (GUI: Device → HA → HA Communications → HA2 → uncheck Session Sync)
# Commit
# Wait 15 seconds
# Re-enable session sync
# Commit

# Step 3: Verify recovery
show high-availability state             # recovering peer should move to passive
show high-availability state-synchronization   # sync should complete
```

**Alternative — graceful HA restart on the recovering peer (after HA2 confirmed up):**

```
request high-availability state suspend
# Wait 10 seconds
request high-availability state functional
# Forces clean re-entry into initial with HA2 now available
```

### Fix — structural (prevent recurrence)

**Option A — Configure HA2-backup link:**

A dedicated HA2-backup interface provides a second path for session sync. If primary HA2 comes up late, backup may be up earlier:

```
Device → High Availability → HA Communications → HA2 Backup Link
# Must use a different physical interface from HA2
```

**Option B — Tune HA2 keep-alive:**

```
Device → High Availability → General → HA2 Keep-Alive:
  Enable: Yes
  Threshold: 30000ms   (default 10000ms)
  Action: Log Only (during testing); SNMP Trap or Failover (production)
```

**Option C — Increase the promotion hold time:**

```
Device → High Availability → General → Timers (Advanced):
  Promotion Hold Time: 5000–10000ms   (default 2000ms — increase for large session tables)
```

---

## 9. Root Cause 3 — Session Synchronization Resource Exhaustion

### Why this happens

On high-throughput firewalls with millions of concurrent sessions, the sync data volume can be substantial. Under certain conditions — particularly immediately after failover on a heavily loaded system — the sync process can exhaust HA2 bandwidth or internal sync buffers.

Contributing factors:
- Session table > 500k sessions
- HA2 link running at 1G on a 10G+ dataplane firewall
- HA2 link shared with other traffic (not dedicated)
- Session sync enabled for both IPv4 and IPv6 on large dual-stack environments simultaneously

### Detection

```
show high-availability state-synchronization
# Sessions synchronized: <number> — should grow over time
# Synchronization status: In-progress / Complete / Failed

show counter global filter aspect ha delta yes
# HA sync-related drop counters

show high-availability interface ha2
# High error count or CRC errors — physical link issue

show high-availability all
# Check HA2 throughput and error counters
```

### Fix — immediate

```
# Prevent HA2 exhaustion from triggering failover during sync burst
Device → High Availability → General → HA2 Keep-Alive → Action: Log Only

# Force a clean sync restart on the active peer:
# Disable then re-enable session synchronization
# Commit after each change
```

### Fix — structural

| Platform | Minimum HA2 Link Speed |
|---|---|
| PA-3200 series | 1G dedicated |
| PA-5200 series | 10G dedicated |
| PA-5400 series | 25G via HSCI |
| PA-7000 series | 40G/100G via HSCI |

HA2 must be a dedicated interface — never share HA2 with management or production traffic.

**Tune session sync scope:**

```
Device → High Availability → Session Synchronization:
  Sync QoS: enable only if QoS policy must survive failover
  Sync User-ID: disable if User-ID rebuilds quickly from the agent
  Sync IPv6 sessions: disable if IPv6 session volume is negligible
```

---

## 10. Root Cause 4 — Split-Brain After Upgrade or HA1 Failure

### Why split-brain happens

Split-brain occurs when both HA peers simultaneously believe they are active. The canonical trigger is HA1 link failure — without HA1, each peer independently decides to become active. Post-upgrade causes include:

- HA1 and HA1-backup share the same failure domain (same switch) — one switch failure kills both
- HA1-backup is missing
- Heartbeat backup is disabled
- Wrong peer HA1 IP configured
- Duplicate HA group IDs
- Preemption fires on the rebooted peer before the other completes upgrade
- Upgrade-related HA1 port mapping or interface issue

### Symptoms

- Both `show high-availability state` outputs show `state: active`
- MAC address flapping on upstream switches — floating IP MAC appears from two interfaces
- ARP tables show the same IP with two different MACs
- Routing protocols receive duplicate hellos from the same neighbor IP
- Traffic is intermittently passing or actively dueling

### Immediate containment

```
# Step 1 — Identify which peer is the correct active
show session info | match num-active    # on both peers
show traffic statistics                 # on both peers
# The peer with more active sessions and correct running config is likely the intended active

# Step 2 — Suspend the wrong peer
request high-availability state suspend

# Step 3 — Verify intended active is now sole active
show high-availability state   # suspended on wrong peer; active on intended peer

# Step 4 — Investigate HA1 before restoring
show interface ha1
show interface ha1-backup
show log system | match ha1
show log system | match election

# Step 5 — Restore suspended peer only after HA1 is confirmed stable
request high-availability state functional
```

### Prevention

**HA1-backup on a different switch** is the single most important preventive measure. If HA1 fails, HA1-backup maintains the control channel and prevents split-brain.

**Enable heartbeat backup** as an additional keepalive path independent of HA1.

**Disable preemption during upgrades** — see Section 14.

---

## 11. Root Cause 5 — Path Monitoring Misconfiguration

### What path monitoring does

Path monitoring watches the reachability of specific IP addresses from the active firewall. If monitored targets become unreachable, the firewall initiates failover. This is correct when targets are genuine upstream infrastructure. It becomes a cascade trigger when:

- Targets are reachable only through the active firewall (e.g., 8.8.8.8, 1.1.1.1)
- Targets are services with planned downtime (not infrastructure)
- Timer thresholds are too aggressive (minor blip triggers failover)
- Too few redundant targets (single target failure triggers failover)
- Failure Condition is set to `Any` when paths are redundant

### The cascade failure pattern

```
Active firewall monitors 8.8.8.8 via upstream router.
  ↓
Upstream router temporarily unreachable (BGP reconverge, link flap).
  ↓
Active firewall cannot reach 8.8.8.8. Path monitoring threshold crossed.
  ↓
Failover occurs. Peer becomes active.
  ↓
Peer also cannot reach 8.8.8.8 — same upstream outage is still in progress.
  ↓
Peer's path monitoring triggers. Peer initiates failover.
  ↓
Original active recovers and becomes active again.
  ↓
Loop continues until upstream recovers.
  ↓
Results in repeated HA flapping that looks like HA instability
  but is actually upstream routing instability amplified by path monitoring.
```

### Bad path monitoring designs

| Bad Design | Why Dangerous |
|---|---|
| Monitoring only one upstream IP | Single failure triggers failover |
| Monitoring 8.8.8.8 or 1.1.1.1 | Only reachable if WAN is up — WAN flap triggers failover on both peers |
| Monitoring a target that rate-limits ICMP | Packet loss under load triggers spurious failover |
| Monitoring a target across a VPN tunnel | VPN flap triggers path monitoring failover |
| Failure Condition = `Any` with redundant paths | One target failure causes failover even when paths are redundant |
| No hold timers | Microflap triggers immediate failover |
| Preemption enabled during unstable conditions | Failover + preemption creates failover loop |

### Fix — target selection

| Target Type | Good or Bad | Why |
|---|---|---|
| Upstream router loopback or management IP | **Good** | Reachable via physical network; router-health indicator |
| ISP first-hop gateway IP | **Good** | Physical network reachable; WAN-independence indicator |
| Core switch L3 IP | **Good** | Reachable via physical network regardless of firewall state |
| Secondary ISP gateway (different provider) | **Good** | Diversity — both must fail for Condition: All to trigger |
| 8.8.8.8 or 1.1.1.1 | **Bad** | Only reachable if WAN is up; cascade trigger |
| Application server IPs | **Bad** | Have planned maintenance; not infrastructure |
| The peer firewall's data plane IP | **Bad** | Creates dependency loops |

### Fix — failure condition

| Setting | Meaning | Recommended Use |
|---|---|---|
| `Any` | Failover if ANY target unreachable | Use when each target represents a different failure domain |
| `All` | Failover only if ALL targets unreachable | **Default recommendation** — more conservative; requires multiple targets to agree on failure |

### Fix — timer tuning

```
Device → High Availability → Path Monitoring:
  Interval:  200ms
  Threshold: 25      (effective timeout = 5 seconds — more conservative than default 10 × 200ms = 2s)
  Failure Condition: All (recommended)
```

---

## 12. Root Cause 6 — HA1 Link Failure or Flapping

### Why HA1 link problems are dangerous

HA1 carries keepalive heartbeats. If HA1 fails, each peer's dead timer eventually expires and each independently concludes the other is dead — both declare themselves active (split-brain). HA1 flapping is worse than a clean failure: each flap resets the dead timer and causes the state machine to oscillate, producing repeated failovers.

### Common HA1 failure causes

| Cause | Detection | Fix |
|---|---|---|
| SFP transceiver incompatibility | `show interface ha1` — physical errors or CRC | Replace with Palo Alto-listed compatible SFP |
| MTU mismatch between HA1 peers | Packet loss at MTU boundary | Match MTU on both HA1 interfaces and any switch in path |
| Spanning tree blocking the HA1 VLAN | Link up but packets lost | Set HA1 VLAN ports to portfast/edge; disable STP on dedicated HA links |
| Switch port error-disabled | Physical port shut by switch | Check switch port status; clear err-disable |
| HA1 over congested management network | Keepalives delayed | Dedicate HA1 to a separate interface and VLAN |
| Wrong peer HA1 IP configured | HA1 never establishes | Correct peer IP in HA configuration |

### Dead timer tuning

```
Device → High Availability → General → Timers (Advanced):
  Dead Interval: 10000ms   (default — appropriate for dedicated direct HA link)
  Hello Interval: 8000ms   (default)

# For HA1 over a routed or congested path — increase proportionally:
  Dead Interval: 30000ms
  Hello Interval: 20000ms
  # Dead interval must always be > Hello interval
```

### HA1 monitoring

```
show interface ha1
show interface ha1-backup
show high-availability link-monitoring
show counter global filter aspect ha | match hello
show counter global filter aspect ha delta yes
```

---

## 13. Root Cause 7 — HSCI / HA3 Link Issues on Chassis Platforms

### PA-7000 and PA-7500 HSCI requirements

| Requirement | Detail |
|---|---|
| Physical port | HSCI-A and HSCI-B on the Switch Management Card (SMC) or NPC — check platform guide for exact slot |
| Cable | 40G/100G DAC for short runs (≤10m); AOC for longer runs — specific part numbers on compatibility matrix |
| Both ports | HSCI-A and HSCI-B should both be cabled for redundancy |
| Transceiver | Must be on the PA-7000/PA-7500 compatibility matrix — generic transceivers will not initialize |
| HSCI-A connection | HSCI-A connects directly to HSCI-A on the peer — do not transit through a switch |

### PA-5400 and PA-5450 HSCI requirements

| Platform | Design Requirements |
|---|---|
| PA-5400 | HSCI can be used for HA2 and HA3. HSCI-A connects directly to HSCI-A on the peer. Data ports may be used for HA2 or HA3, but the same data port cannot be used for both HA2 and HA3 simultaneously |
| PA-5450 | HSCI-A and HSCI-B can be used for HA2, HA3, or both. HSCI-A connects to HSCI-A. HSCI-B can be backup. If HA2 is configured on dataplane ports, both HA2 and HA2-backup must be on dataplane interfaces |

### Common HSCI failure modes and fixes

**HSCI link not initializing:**

```
# Check HSCI port status
show chassis status
show interface hsci-a
show interface hsci-b
```

| Cause | Fix |
|---|---|
| Wrong cable type (passive DAC on run > 10m requiring AOC) | Replace with supported AOC; check compatibility matrix |
| Transceiver not on compatibility matrix | Replace with listed compatible transceiver |
| HSCI ports not configured correctly in HA settings | Verify HSCI configuration per platform guide |
| Both HSCI links transiting the same switch | Direct-connect between chassis; remove switch transit |
| Mixed HSCI and dataplane interface on unsupported platform | Verify supported HA port combinations per platform; correct combination |

```
# Verify HSCI configuration
show high-availability state | match hsci

# Identify current transceiver
show interface hsci-a | match transceiver
# Cross-reference: https://docs.paloaltonetworks.com/compatibility-matrix
```

### HA3 on non-chassis (software) platforms

```
# Configure HA3
Device → High Availability → Active/Active Config → Packet Forwarding → HA3 Interface

# Check HA3 link state
show interface ha3

# Check HA3 forwarding counters
show counter global filter aspect ha3 delta yes
```

HA3 must be sized for peak asymmetric forwarding throughput. An undersized HA3 link is a performance bottleneck in A/A under asymmetric load. Do not place HA3 through Layer 3 infrastructure — it carries Layer 2 HA forwarding frames.

---

## 14. Root Cause 8 — Priority / Preemption Misconfiguration

### The post-upgrade preemption trap

1. Peer A (priority 100 — higher priority) is the original active
2. Peer B (priority 200) is passive
3. Peer B is upgraded first (correct sequence), reboots, re-joins as passive
4. Peer A is upgraded; Peer A reboots
5. During Peer A's reboot, Peer B becomes active (correct — it's the only one running)
6. Peer A completes boot, checks: "Am I higher priority? Is preemption enabled?" → Yes → Peer A preempts immediately
7. Failover occurs before sessions are fully synchronized → sessions drop

**Worse scenario:** Peer A takes longer than expected to boot (large config, slow storage). Peer B has been active for an extended period, accumulating new sessions. When Peer A preempts, those sessions that weren't on Peer A's pre-upgrade table are orphaned.

### Detection

```
show high-availability state | match preempt
show high-availability state | match priority
show log system | match preempt
```

### Fix — preemption tuning

**Option 1 — Disable preemption during upgrades:**

```
Device → High Availability → General → Election Settings:
  Preemptive: No   (uncheck on the higher-priority peer)
  Commit
# Re-enable after upgrade is complete and HA is confirmed stable
```

**Option 2 — Extend preemption hold time:**

```
Device → High Availability → General → Timers (Advanced):
  Preemption Hold Time: 60000ms
  # Default is 1000ms (1 second) — far too short for session sync to complete
  # Consider 30000–60000ms for high-session-volume environments
```

**Option 3 — Equal priority:**

Setting both peers to the same priority disables priority-based preemption while still allowing automatic failover:

```
Device → High Availability → General → Priority: 100   (same value on both peers)
Device → High Availability → General → Preemptive: No
```

---

## 15. Root Cause 9 — PAN-OS, Content, License, or Feature Mismatch

This is distinct from plugin mismatch (Section 7). HA peers require compatible software, content, licenses, and feature capabilities across multiple dimensions. A peer showing `non-functional` with no obvious link problem is often caused by a feature or capability mismatch.

### Items to compare between peers

| Item | Why It Matters |
|---|---|
| PAN-OS version | Peers must be on compatible versions during steady state and upgrade sequencing |
| App, Threat, Antivirus, WildFire, URL content versions | Content mismatch can affect App-ID, policy enforcement, and runtime behavior |
| Installed plugins | Plugin mismatch alters the supported feature set |
| License state | Feature availability differs if license state differs between peers |
| Multi-VSYS capability | HA peer capabilities must align |
| GTP / SCTP / VPN capabilities | Feature mismatch can block or degrade synchronization |
| FIPS or CC mode | Security mode differences affect compatibility |
| Interface type and HA link type | HA ports must match platform and HA design |
| Virtual systems configuration | VSYS count and capability must be compatible |

### Detection

```
show system info           # PAN-OS version, model, serial, features
show plugins installed     # plugin versions and states
request license info       # license state
show high-availability all # HA compatibility status
```

### Fix

1. Compare each item in the table above between both peers
2. Align content versions: `request content upgrade install` on the lagging peer
3. Align plugin versions: Section 7 procedure
4. Align license state: contact Palo Alto support if license differs unexpectedly
5. Align feature configuration: ensure multi-VSYS, GTP, SCTP, VPN are enabled/disabled consistently
6. Commit both peers after each alignment step
7. Verify HA state after each step before proceeding to the next

---

## 16. Active/Active-Specific HA Issues

### 16.1 Session ownership and HA3 forwarding

In A/A, sessions are owned by one of the two peers. If return traffic arrives at the non-owning peer, it must be forwarded over HA3 to the owner for processing.

```
# Check HA3 link state
show interface ha3

# Check HA3 forwarding counters
show counter global filter aspect ha3 delta yes

# Check session ownership for a specific session
show session id <id> | match owner
```

**HA3 failure results:** If HA3 is down, asymmetric sessions cannot be forwarded → sessions drop. If HA3 is undersized, high asymmetric load causes packet drops at peak.

### 16.2 Floating IP ownership

In A/A, floating IPs are owned by one peer at a time. Incorrect distribution or dual-claiming causes routing and NAT failures.

```
show high-availability virtual-address
show arp all | match <floating-ip>
```

### 16.3 Tentative state in Active/Active

`Tentative` is A/A-specific — a peer re-learning session state after link or path recovery. Normal duration is seconds. Persistent `tentative` (> 60 seconds) indicates HA3 instability or session sync collision.

```
show high-availability state   # check for tentative

# If stuck in tentative:
request high-availability state suspend
# Wait 30 seconds
request high-availability state functional
```

### 16.4 Device binding for NAT in A/A

NAT rules in A/A should be bound to specific device IDs for consistent translation. A device-binding mismatch causes one peer to not apply NAT to sessions it owns, while the other applies NAT to sessions it doesn't own — producing unpredictable source addresses. See KB-PAN-NAT-001 for full NAT/A/A coverage.

```
show running nat-policy | match device
show high-availability state | match device-id
```

---

## 17. Platform-Specific HA Link Design

### 17.1 Physical link requirements

| Link | Physical Requirement | Switch Requirement |
|---|---|---|
| HA1 | Dedicated interface; not shared with management or data | Portfast/edge port; STP disabled; dedicated VLAN |
| HA1-backup | Different physical interface; different switch from HA1 | Same as HA1 — must be a truly separate failure domain |
| HA2 | Dedicated interface; minimum speed = data plane tier | Portfast/edge; STP disabled; dedicated VLAN; no QoS shaping |
| HA2-backup | Different physical interface; different switch from HA2 | Same requirements as HA2 |
| HA3 (A/A only) | Must handle asymmetric forwarding peak throughput | Direct connect preferred; do not route through L3 infrastructure |
| HSCI (chassis) | Both HSCI-A and HSCI-B cabled; direct connect between chassis | Do not transit through a switch |

### 17.2 VLAN and L2 design rules

- Each HA link should be on its own dedicated VLAN
- HA VLANs: STP disabled on the port (portfast/edge); BPDU guard optional
- HA links must not traverse a trunk that also carries production traffic
- For chassis HSCI: direct-connect between chassis is required where documentation specifies it — do not transit through a switch

### 17.3 HA1 over routed networks

HA1 can operate over a routed network (IP-based HA1) for geographically separated pairs. Enable encryption for routed HA1.

```
Device → High Availability → HA Communications → HA1:
  Encryption: Enable (required when HA1 traverses untrusted network)
  Peer IP: <peer's HA1 IP reachable over the routed path>

# Increase timers proportionally for routed path latency:
Dead Interval: 30000ms
Hello Interval: 20000ms
```

### 17.4 Link monitoring vs. path monitoring

| Feature | Monitors | Trigger | When to Use |
|---|---|---|---|
| Link Monitoring | Physical HA link state | Physical link down → failover | Always — minimum viable HA monitoring |
| Path Monitoring | IP reachability via data plane | Target unreachable → failover | Use conservatively; infrastructure IPs only |

Never disable link monitoring. Path monitoring should use `Failure Condition: All` with multiple stable infrastructure targets.

---

## 18. Path Monitoring — Design and Tuning

### Recommended target selection

| Target Type | Good? | Reason |
|---|---|---|
| Upstream router loopback or management IP | Yes | Reachable via physical network regardless of firewall; router-health indicator |
| ISP first-hop gateway | Yes | Physical network reachable; WAN-independence indicator |
| Core switch L3 IP | Yes | Reachable via physical network independently of firewall state |
| Secondary ISP gateway (different provider) | Yes | Diversity — both must fail for Condition: All to trigger |
| 8.8.8.8 or 1.1.1.1 | No | Only reachable if WAN is up; cascade trigger on WAN flap |
| Application server IPs | No | Planned maintenance; not infrastructure |
| Peer firewall data plane IP | No | Dependency loop |
| VPN-only reachable targets | No | VPN flap triggers path monitoring failover |

### Timer recommendations by deployment type

| Deployment | Interval | Threshold | Effective Timeout | Failure Condition |
|---|---|---|---|---|
| Same-rack HA | 200ms | 10 | 2 seconds | Any (if 2+ diverse targets) |
| Campus edge (different switches) | 200ms | 25 | 5 seconds | All |
| Geo-separated HA | 1000ms | 10 | 10 seconds | All |
| Virtual wire HA | 200ms | 25 | 5 seconds | All |

### Disabling preemption during path instability

Disable preemption before any period where path monitoring targets may be temporarily unreachable (ISP maintenance, BGP reconvergence, upstream switch upgrade):

```
Device → High Availability → Election Settings → Preemptive: No
Commit
# Re-enable only after the monitored environment is confirmed stable
```

### Verification

```
show high-availability all   # includes path monitoring section
show high-availability transitions   # shows failover events and their causes

# Simulate a path monitoring failure (does not trigger failover — test only)
test high-availability path-monitoring
```

---

## 19. Recovery Runbooks

### Runbook A — Peer stuck in Initial: Waiting for state synchronization completion

```
1. Confirm HA2 state:
   show high-availability interface ha2
   show high-availability state-synchronization

2. If HA2 is physically down:
   Fix cabling, interface type, peer IP, subnet, VLAN, HSCI connection, or transport mismatch
   Confirm HA2 shows up on both peers

3. If HA2 is slow post-upgrade and peer is stuck in Initial:
   Temporarily disable session synchronization on both peers (GUI: Device → HA → HA2 → uncheck)
   Commit on both peers
   Confirm the stuck peer becomes Passive

4. Fix HA2 permanently (address the underlying cause)

5. Re-enable session synchronization
   Commit on both peers

6. Confirm state-sync counters increment:
   show high-availability state-synchronization

7. Test controlled failover during a maintenance window
```

### Runbook B — Plugin mismatch causing stuck in Initial after failover

```
1. Compare plugin state on both peers:
   show plugins installed   (on both)

2. Identify differences in name, version, or state

3. If plugin is not required: uninstall from both peers

4. If plugin is required: install the same supported version on both peers
   request plugins download <name> version <version>
   request plugins install <name> version <version>

5. Commit both peers (reboot only if required by plugin documentation)

6. Confirm HA state and configuration synchronization:
   show high-availability all
   request high-availability sync-to-remote running-config

7. Re-enable session sync if it was temporarily disabled during fix
```

### Runbook C — Split-brain after upgrade

```
1. Identify whether both peers are active:
   show high-availability state   (on both)

2. Choose the correct active firewall based on:
   - Correct running configuration
   - Active route adjacencies
   - Current production traffic and session counts
   - Current NAT/session state
   - Panorama commit state
   - Correct content and plugin versions

3. Suspend the incorrect peer:
   request high-availability state suspend

4. Restore HA1 and HA1-backup:
   show interface ha1
   show interface ha1-backup
   Fix any physical, VLAN, STP, or IP addressing issue

5. Enable heartbeat backup where appropriate

6. Verify HA1 and HA1-backup stability before proceeding

7. Return the suspended peer to functional:
   request high-availability state functional

8. Confirm expected state:
   show high-availability state
   show high-availability all
```

### Runbook D — Repeated failover due to path monitoring

```
1. Immediately disable preemption:
   Device → High Availability → Election Settings → Preemptive: No
   Commit

2. Review path monitoring targets:
   show high-availability all   (path monitoring section)

3. Remove unreliable ICMP targets (public DNS, application servers)

4. Add at least two stable targets per critical path
   (upstream router loopbacks, ISP gateways, core switch L3 IPs)

5. Change Failure Condition to All if using redundant paths

6. Increase monitor fail hold-up time (Threshold × Interval to 5+ seconds)

7. Commit

8. Observe for stability over at least one business hour

9. Re-enable preemption only after the monitored environment is confirmed stable
   and a controlled failover test passes
```

---

## 20. Upgrade Runbook for HA Pairs

### Pre-upgrade checklist

- [ ] Both peers in clean state: `show high-availability state` — one active, one passive, session sync active
- [ ] Plugin version parity: `show plugins installed` — every plugin identical on both peers
- [ ] HA link health: `show high-availability link-monitoring` — all links up on both peers
- [ ] Session sync active and healthy: `show high-availability state-synchronization`
- [ ] No pending commits or configuration changes on either peer
- [ ] Content versions compatible: `show system content-version` on both peers
- [ ] Configuration backup saved: **Device → Setup → Operations → Export Named Configuration Snapshot** on both peers
- [ ] Device state exported from both peers
- [ ] Preemption disabled on higher-priority peer: `Device → HA → General → Preemptive: No` + commit
- [ ] Path monitoring is stable — no flapping before the upgrade window begins
- [ ] Panorama confirmed NOT pushing different template or plugin configuration to each peer independently
- [ ] Management reachability confirmed to both peers independently
- [ ] Rollback path confirmed: `show system software installed` shows previous version available
- [ ] Palo Alto release notes reviewed for the target version for any HA-specific known issues
- [ ] Maintenance window scheduled and change record opened

### Upgrade sequence — Active/Passive

```
Phase 1: Upgrade the passive peer first

1. On the PASSIVE peer:
   request system software download version <target-version>
   request system software install version <target-version>
   request restart system

2. Wait for the passive peer to complete boot and rejoin HA:
   show high-availability state          # should show: passive
   show high-availability state-synchronization   # sync should complete

3. Verify plugin versions match after passive peer boots:
   show plugins installed   (on both peers — must be identical)

4. Verify content versions are aligned:
   show system content-version   (on both peers)

5. DO NOT proceed to Phase 2 if:
   - Plugin versions differ
   - HA state is not clean (passive + active with sync complete)
   - Any HA link is down

Phase 2: Upgrade the active peer

6. On the ACTIVE peer:
   request system software install version <target-version>
   request restart system
   # Traffic fails over to the passive (now-upgraded) peer

7. Wait for the previously-active peer to boot and rejoin HA:
   show high-availability state          # should show: passive
   show high-availability state-synchronization   # sync should complete

8. Verify plugin versions match:
   show plugins installed   (on both)

9. If stuck-in-initial occurs:
   - Check HA2: show high-availability interface ha2
   - If HA2 up: toggle session sync (Section 8 fix)
   - If plugin mismatch: fix plugins (Section 7 fix)
   - If feature mismatch: Section 15 fix

Phase 3: Post-upgrade validation

10. Run full post-upgrade validation (Section 21)

11. Re-enable preemption if desired:
    Device → High Availability → General → Preemptive: Yes
    Commit on higher-priority peer
    Wait for preemption hold time before traffic shifts
```

### During upgrade — do not

- Upgrade both peers simultaneously
- Change HA cabling during the upgrade window
- Change HA1 encryption during the same window unless specifically planned
- Introduce plugin changes at the same time as PAN-OS upgrade unless required
- Proceed to Phase 2 before Phase 1 is fully stable

### Upgrade sequence — Active/Active

Same passive-first principle (upgrade device ID 1 first, then device ID 0). Additional post-upgrade checks:

```
show high-availability virtual-address   # floating IPs on correct owners
show interface ha3                       # HA3 link up
show session all | match owner           # session ownership distributed correctly
```

---

## 21. Post-Failover Validation and Final Resolution Criteria

Run this sequence after every planned or unplanned failover, and after every upgrade. The issue is resolved only when **all** conditions pass.

### Validation commands

```
# 1. HA state — both peers
show high-availability state
show high-availability all
show high-availability transitions
# Expected: one active, one passive; no repeated transitions; no split-brain

# 2. HA link health
show high-availability link-monitoring
# Expected: HA1, HA2, HA1-backup, HA2-backup (where configured) all up

# 3. Session sync status
show high-availability state-synchronization
# Expected: synchronization complete; session count similar to active peer

# 4. Path monitoring
show high-availability all   # path monitoring section
# Expected: all monitored targets reachable; no path monitoring flaps

# 5. Plugin and feature parity
show plugins installed   (on both peers)
show system info         (on both peers)
# Expected: identical plugins, versions, and PAN-OS version

# 6. Config synchronized
show high-availability all | match config
# Expected: Running Config: Synchronized

# 7. Session count comparison
show session info | match num-active   (on both peers)
# Expected: passive peer within 5–10% of active peer

# 8. HA3 / floating IPs (A/A)
show high-availability virtual-address
show interface ha3
show arp all | match <floating-ip>

# 9. Counter health
show counter global filter aspect ha delta yes
# Expected: no incrementing error counters

# 10. System log clean since failover
show log system direction equal backward | match ha
# Expected: no unexpected failover events or HA errors since the event
```

### Final resolution criteria checklist

| Required Condition | Pass/Fail |
|---|---|
| Correct local state and correct peer state | [ ] |
| Peer connection status up | [ ] |
| HA1 up | [ ] |
| HA1-backup up (if configured) | [ ] |
| HA2 up (if session synchronization is enabled) | [ ] |
| HA2-backup up (if configured) | [ ] |
| HA3 up (if Active/Active) | [ ] |
| Running configuration synchronized | [ ] |
| No plugin mismatch | [ ] |
| No feature or license mismatch | [ ] |
| No repeated HA transitions | [ ] |
| No path monitoring flaps | [ ] |
| No split-brain | [ ] |
| Session synchronization counters incrementing | [ ] |

> **Closure standard:** The firewall should not merely be "not broken right now." It should survive a controlled failover and return to a stable HA state without manual intervention. Perform a manual failover test before declaring the incident closed.

### Manual failover test

```
# On the ACTIVE peer — initiate a manual failover:
request high-availability state suspend
# Traffic should shift to passive peer within the failover timer

# Verify:
show high-availability state   # suspended on initiator; active on peer
show traffic statistics         # confirm traffic flowing on new active

# Restore:
request high-availability state functional

# Verify restored peer becomes passive and syncs:
show high-availability state
show high-availability state-synchronization
```

---

## 22. Preventive Design Checklist

| Area | Checklist |
|---|---|
| **HA1** | Use dedicated HA1 where available. Configure HA1-backup on a different interface and different switch. Enable heartbeat backup where appropriate. Confirm peer HA1 IP and backup peer HA1 IP. Do not share HA1 with management or production traffic |
| **HA2** | Use dedicated HA2 or HSCI where supported. Configure HA2-backup. Enable HA2 keep-alive and tune threshold. Avoid unreliable switched paths. Verify state-sync counters after failover and upgrade. Size HA2 link to match dataplane throughput tier |
| **HA3** | Required for Active/Active. Use HSCI where supported. Ensure MTU supports HA3 encapsulation (enable jumbo frames where required). Do not route HA3 through Layer 3 infrastructure |
| **HSCI** | Direct-connect HSCI-A to HSCI-A on the peer where documentation requires direct connection. Do not mix HSCI and dataplane interfaces where unsupported. Use only transceivers and cables on the compatibility matrix |
| **Monitoring** | Tune path monitoring to real forwarding-path failure. Use stable infrastructure targets only. Avoid single-target configurations. Use Failure Condition: All for redundant paths. Use hold timers. Disable preemption during maintenance |
| **Software and plugins** | Keep PAN-OS versions aligned. Keep content versions aligned. Keep plugin versions identical — remove unused plugins from both peers. Avoid partial plugin upgrades. Confirm Panorama is not pushing divergent configuration to each peer |
| **Upgrade** | Upgrade passive peer first. Verify HA stability between phases. Disable preemption before starting. Confirm plugin parity after each phase. Do not upgrade both peers simultaneously |

---

## 23. Known Traps and Exact Fixes

| Trap | Wrong Assumption | Correct Logic | Fix |
|---|---|---|---|
| Plugin mismatch causes stuck-in-initial | "HA1 is up so session sync should work" | Session sync checks plugin compatibility before transmitting; mismatch prevents sync entirely regardless of link state | Match plugin versions on both peers; temporarily disable session sync while upgrading plugins |
| Upgrading the active peer first | "It doesn't matter which peer I upgrade first" | Upgrading active causes immediate failover to the unupgraded passive; creates a version-mismatch window | Always upgrade the passive peer first; verify sync complete before upgrading active |
| Disabling session sync to fix stuck-in-initial and forgetting to re-enable | "Session sync is optional / I'll re-enable it later" | Without session sync, all sessions drop on failover — cold standby only | Always re-enable session sync immediately after the fix; verify with `show high-availability state-synchronization` |
| Path monitoring targeting 8.8.8.8 | "8.8.8.8 is always reachable and reliable" | 8.8.8.8 is only reachable if the firewall's WAN path is up; WAN flap triggers failover on both peers simultaneously | Replace with infrastructure IPs: upstream router loopback, ISP gateway, core switch |
| Both HSCI ports transiting same switch | "Any switch is fine for HSCI transit" | One switch failure takes down both HSCI links simultaneously | Direct-connect HSCI between chassis; never transit through a shared switch |
| Preemption enabled without extended hold time | "Preemption is for fast recovery — default 1 second is fine" | 1-second hold time fires before session sync completes; preempting active has stale session table | Extend preemption hold time to 30–60 seconds; disable preemption during upgrades |
| Relying on HA link-up to confirm HA health | "HA1 is up so HA is working" | HA1 up + session sync disabled = HA is up but failover drops all sessions | Run full validation (Section 21); specifically check session sync status |
| HA2 shared with management VLAN | "Management VLAN has spare bandwidth" | HA2 session sync bursts can saturate shared VLANs; management access drops | Dedicate a separate physical interface and VLAN to HA2 |
| Not testing failover after upgrade | "The upgrade completed without errors so HA is fine" | HA state can appear correct while session sync is degraded or path monitoring is misconfigured | Always perform a manual failover test after upgrades (Section 21) |
| Mixing HSCI and dataplane ports on PA-5400 | "Any combination should work since both are supported individually" | Unsupported combinations can cause commit failure or unstable HA behavior | Verify supported HA port combinations in platform-specific documentation before configuring |
| `non-functional` treated as a generic reboot fix | "`non-functional` means broken hardware — reboot will fix it" | `non-functional` usually indicates a feature, license, or capability mismatch that survives reboots | Collect logs before rebooting; identify the specific mismatch (Section 15); align configurations |
| HA declared healthy without a failover test | "Everything looks green in the dashboard" | Dashboard shows link state and sync status but does not prove the passive can actually take over | Perform a controlled failover test to the passive peer before closing any HA incident |

---

## 24. CLI and GUI Diagnostic Reference

### 24.1 HA state and health commands

```
# HA state summary — run on BOTH peers
show high-availability state
show high-availability all
show high-availability transitions          # history of state changes

# Session synchronization status
show high-availability state-synchronization
show high-availability interface ha2        # HA2-specific status

# Link monitoring (HA1, HA2, backup links)
show high-availability link-monitoring

# HA statistics (packet counts, errors)
show high-availability all                  # comprehensive output including stats

# Floating IP ownership (A/A)
show high-availability virtual-address

# HA-related global counters
show counter global filter aspect ha delta yes
show counter global filter delta yes severity drop | match ha
```

### 24.2 Interface and link diagnostics

```
show interface ha1
show interface ha1-backup
show interface ha2
show interface ha2-backup
show interface ha3        # A/A only
show interface ha-control
show interface all | match ha

# Chassis platforms
show chassis status
show interface hsci-a
show interface hsci-b
```

### 24.3 Plugin, version, and license diagnostics

```
# Plugin versions (run on both peers — must be identical)
show plugins installed
request plugins check

# PAN-OS and system info
show system info

# Available plugin versions
request plugins check

# License state
request license info

# Jobs in progress (useful if upgrade or install is in flight)
show jobs all
```

### 24.4 System and HA agent logs

```
# System log — HA events
show log system direction equal backward | match ha
show log system direction equal backward | match failover
show log system direction equal backward | match plugin
show log system direction equal backward | match split
show log system direction equal backward | match preempt
show log system direction equal backward | match election
show log system direction equal backward | match suspend
show log system direction equal backward | match path-monitor

# Full recent system log
show log system direction equal backward

# HA agent and management plane logs (for deep diagnosis / TAC escalation)
less mp-log ha_agent.log
tail follow yes mp-log ha_agent.log
less mp-log configd.log
less mp-log ms.log
```

### 24.5 HA operational commands

```
# Suspend a peer (remove from forwarding / HA election)
request high-availability state suspend

# Restore a suspended peer
request high-availability state functional

# Push configuration from active to passive
request high-availability sync-to-remote running-config

# Toggle session sync (fix for stuck-in-initial — run on active peer)
# Disable, commit, wait, re-enable, commit
# GUI: Device → High Availability → HA Communications → HA2 → Session Synchronization

# Manual path monitoring test (does not trigger failover)
test high-availability path-monitoring
```

### 24.6 GUI diagnostic path

```
Dashboard → High Availability widget:
  Shows both peer states, link status, sync status

Device → High Availability:
  All HA configuration and link/path monitoring settings

Monitor → Logs → System:
  Filter: subtype eq ha
  Provides timeline of all HA state transitions and errors

Monitor → Logs → System:
  Filter: eventid contains ha
  Broader HA event filter
```

---

## 25. Change-Control Checklist

For any HA configuration change, upgrade, or link modification:

| Check | Question | Pass Condition |
|-------|----------|----------------|
| Pre-change HA state | Both peers in clean state before starting? | `show high-availability state` shows expected state on both peers |
| Plugin parity | Identical plugin versions on both peers? | `show plugins installed` output matches on both |
| Feature/license parity | PAN-OS, content, licenses, and feature capabilities aligned? | `show system info` and `request license info` match on both peers |
| HA link health | All links up (HA1, HA1-backup, HA2, HA2-backup, HA3 if A/A)? | `show high-availability link-monitoring` shows all links operational |
| Session sync health | Session sync active and current? | `show high-availability state-synchronization` shows sync complete |
| Preemption disabled | Preemption disabled for the duration of the upgrade? | `show high-availability state | match preempt` confirms disabled on higher-priority peer |
| Upgrade sequence | Passive peer being upgraded first? | Upgrade runbook confirms passive-first |
| Config backup | Snapshot saved and device state exported on both peers? | Confirmed in Device → Setup → Operations |
| Rollback path | Previous PAN-OS version available? | `show system software installed` shows previous version |
| Path monitoring targets | Targets are infrastructure IPs, not dependent on the firewall? | Target list reviewed; no public DNS or application servers |
| Post-change validation | Section 21 validation sequence planned? | Checklist prepared |
| Failover test | Manual failover test planned after change? | Test procedure confirmed in maintenance window plan |

---

## 26. Escalation Bundle

Collect from both firewalls before rebooting or making changes. HA failures are time-sensitive — evidence may be overwritten.

### Immediate data collection (before any changes)

- [ ] `show high-availability state` — from BOTH peers simultaneously
- [ ] `show high-availability all` — from BOTH peers
- [ ] `show high-availability transitions` — from BOTH peers
- [ ] `show high-availability state-synchronization` — from BOTH peers
- [ ] `show high-availability interface ha2` — from BOTH peers
- [ ] `show plugins installed` — from BOTH peers
- [ ] `show system info` — from BOTH peers
- [ ] `request license info` — from BOTH peers
- [ ] `show jobs all` — from BOTH peers
- [ ] `show log system direction equal backward` — from BOTH peers
- [ ] `show counter global filter aspect ha delta yes` — from BOTH peers
- [ ] `show interface ha1`, `ha2`, `ha1-backup`, `ha2-backup` — from BOTH peers
- [ ] Timeline: when did problem start; what changed immediately before (upgrade, commit, Panorama push, link change)

### Full escalation package

- [ ] Tech support file from BOTH peers (even if one is non-functional): **Device → Support → Generate Tech Support File**
- [ ] Device state export from both peers
- [ ] Panorama logs if managed: confirm whether a policy push, plugin push, or template push occurred around the event time
- [ ] Switch/network logs: MAC address table, STP events, port error logs for all HA link ports
- [ ] For HSCI issues: cable type, length, part number; transceiver part number; chassis slot configuration
- [ ] For path monitoring issues: full list of monitored targets and their current reachability from both peers
- [ ] HA cabling diagram
- [ ] Switchport configuration for HA links if HA links traverse switches
- [ ] Exact upgrade path (version before, version after, sequence, timing)
- [ ] Whether session sync was enabled, HA2 keep-alive was enabled, preemption was enabled, path monitoring was enabled
- [ ] Whether both peers ever simultaneously showed `active`

**Do not:**
- Clear sessions or reboot either peer before collecting the above
- Make configuration changes before collecting the above
- Escalate with only one peer's data — HA problems always require both peers' perspective

---

## 27. PCNSE-Style Quick Answer Key

| Question Pattern | Correct Answer |
|---|---|
| What does the `initial` HA state mean? | The firewall is synchronizing session state from the active peer before it can forward traffic. It cannot become active until synchronization completes or is bypassed. `initial` is evidence that HA negotiation or synchronization is incomplete — not a cosmetic delay |
| Stuck in `initial` after PAN-OS upgrade. First thing to check? | Plugin version parity: `show plugins installed` on both peers. Plugin mismatch is the most common post-upgrade stuck-in-initial cause |
| Both firewalls show `active`. What is this and how do you resolve it? | Split-brain. Identify which peer is passing traffic (session counts, traffic logs, switch MAC tables). Suspend the wrong peer with `request high-availability state suspend`. Investigate and restore HA1 before returning to functional |
| Why does upgrading the active peer first cause problems? | It triggers an immediate failover to the passive (unupgraded) peer. The passive becomes active while on the old version, creating a version-mismatch window when the upgraded peer tries to rejoin |
| Which HA link carries session table synchronization? | HA2 — the session synchronization link |
| HA2 came up after HA1 post-upgrade — peer stuck in initial. Fix? | Confirm HA2 is now up with `show high-availability interface ha2`. Then toggle session sync on the active peer (disable then re-enable and commit) to force a fresh synchronization attempt |
| What is the risk of temporarily disabling session synchronization? | The passive peer has no session table. If failover occurs while sync is disabled, all existing sessions drop. Re-enable sync and confirm completion before declaring the issue resolved |
| Path monitoring triggering repeated failovers. Most common cause? | Monitored targets (e.g., 8.8.8.8) are only reachable through the active firewall. WAN or upstream flap makes them unreachable on both peers → cascade failover. Replace with infrastructure IPs reachable via the physical network |
| What does HSCI carry on PA-7000 and PA-5400 platforms? | The equivalent of HA1, HA2, and HA3 over a dedicated high-bandwidth link between chassis peers |
| Higher-priority peer preempts immediately after upgrade. Sessions drop. How to prevent? | Extend `Preemption Hold Time` to 30–60 seconds, or disable preemption before the upgrade window and re-enable only after HA is confirmed stable and session sync is complete |
| What is the `tentative` state? | Active/Active only. A peer re-learning session state after a link or path recovery. Normal duration is seconds. Persistent tentative indicates HA3 instability or session sync collision |
| A firewall shows `non-functional`. What is the first thing to investigate? | PAN-OS, content, license, or feature capability mismatch between peers — not a reboot problem. Collect `show system info`, `show plugins installed`, `request license info` from both peers before making any change |
| When is HA declared fully resolved? | When all conditions in the final resolution checklist (Section 21) pass AND a controlled failover test completes successfully with the passive peer taking over and returning to passive without manual intervention |

---

## 28. References

| ID | Reference | URL | Used For |
|----|-----------|-----|----------|
| R1 | Palo Alto Networks: HA Firewall States | https://docs.paloaltonetworks.com/ngfw/administration/high-availability/ha-firewall-states | HA state machine, state definitions, transition logic |
| R2 | Palo Alto Networks: Reference — HA Synchronization | https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/high-availability/reference-ha-synchronization | Session sync dependencies, sync counters, HA2 behavior |
| R3 | Palo Alto Networks: HA Ports on Palo Alto Networks Firewalls | https://docs.paloaltonetworks.com/ngfw/administration/high-availability/ha-ports-on-palo-alto-networks-firewalls | HA port types, HSCI, platform-specific port requirements |
| R4 | Palo Alto Networks: HA Links and Backup Links | https://docs.paloaltonetworks.com/ngfw/administration/high-availability/ha-links-and-backup-links | HA1, HA2, HA3, backup link configuration and design |
| R5 | Palo Alto Networks: Define HA Failover Conditions | https://docs.paloaltonetworks.com/ngfw/administration/high-availability/set-up-activepassive-ha/define-ha-failover-conditions | Path monitoring, link monitoring, failover condition configuration |
| R6 | Palo Alto Networks: HA Timers | https://docs.paloaltonetworks.com/ngfw/administration/high-availability/ha-timers | Dead interval, hello interval, promotion hold time, preemption hold time |
| R7 | Palo Alto Networks: HA Communications Settings | https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-web-interface-help/device/device-high-availability/ha-communications | HA2 keep-alive, session sync, HA2 transport configuration |
| R8 | Palo Alto Networks: Upgrade an HA Firewall Pair | https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-upgrade/upgrade-pan-os/upgrade-the-firewall-pan-os/upgrade-an-ha-firewall-pair | Correct upgrade sequence, passive-first, validation steps |
| R9 | Palo Alto Networks KB: Firewall Stuck in Initial — Waiting for State Synchronization | https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000kFw3CAE | Stuck-in-initial causes, session sync workaround, permanent fix |
| R10 | Palo Alto Networks KB: Firewall Stuck in Initial — Leaving Suspended State | https://knowledgebase.paloaltonetworks.com/kcsArticleDetail?id=kA10g000000PLZe | Suspended state recovery procedure |
| R11 | Palo Alto Networks KB: Plugin Mismatch Causing HA Initial State After Failover | https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA1Ki000000TO8lKAG | Plugin mismatch detection, fix, and prevention |
| — | Palo Alto Networks: Set Up Active/Passive HA | https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/high-availability/set-up-activepassive-ha | A/P HA configuration and link requirements |
| — | Palo Alto Networks: Set Up Active/Active HA | https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/high-availability/set-up-activeactive-ha | A/A HA configuration, session ownership, HA3 |
| — | Palo Alto Networks: Compatibility Matrix | https://docs.paloaltonetworks.com/compatibility-matrix | Supported SFP, DAC, AOC transceivers for HA and HSCI links |
| — | Palo Alto Networks: Plugin Management | https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/plugins | Plugin install, upgrade, and version management |

---

## 29. Revision History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-05-10 | Original — engineering KB (MD): six-state machine table, HA link architecture reference tables, 8 root causes, DIPP/A/A session ownership, floating IPs, tentative state, HA link design best practices, path monitoring timer table by deployment type, upgrade runbook as procedural script, post-failover validation, manual failover test, known traps table, full CLI cheat sheet, PCNSE Q&A |
| 1.1 | 2026-05-10 | Original — formal KB (DOCX): first-principles four-condition model, observed-state interpretation table with immediate focus guidance, PAN-OS/content/license/feature mismatch as distinct root cause (Section 15), VM-Series in scope, HA1-B dataplane-restart platform note, heartbeat backup concept, Panorama push mismatch risk, `less mp-log ha_agent.log` / `tail follow yes mp-log ha_agent.log` / `configd.log` / `ms.log` commands, `show high-availability transitions` and `show high-availability state-synchronization` commands, `show high-availability interface ha2`, PA-5400/PA-5450 HSCI design requirements table, four recovery runbooks (A/B/C/D), final resolution criteria checklist with pass/fail table, closure standard callout, 11 cited official references with URLs |
| 2.0 | 2026-05-10 | Merged — consolidated both sources; added first-principles four-condition model, observed-state interpretation table, PAN-OS/content/license/feature mismatch root cause, PA-5400/PA-5450 HSCI design requirements, heartbeat backup, HA agent log commands (`ha_agent.log`, `configd.log`, `ms.log`), `show high-availability transitions`, `show high-availability state-synchronization`, `show high-availability interface ha2`, four recovery runbooks, final resolution criteria pass/fail checklist, closure standard, `show jobs all`, device state export, Panorama push divergence risk, 11 cited official references with URLs, and the complete preventive design checklist |

> **Maintenance recommendation:** Review this KB after major PAN-OS upgrades, plugin updates, chassis hardware changes, or HA topology modifications. HA failures are largely preventable — the pre-upgrade checklist in Section 20 and the preventive design checklist in Section 22 eliminate the majority of escalations seen in production.

*End of Article KB-PAN-HA-001*
