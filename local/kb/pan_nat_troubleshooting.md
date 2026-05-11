---
kb_id: KB-PAN-NAT-001
title: NAT on Palo Alto Networks NGFW — VPN, U-Turn, Policy Zones, and Destination NAT
triggers:
  - nat policy
  - nat rule
  - nat rules
  - pan-os nat
  - panos nat
  - nat configuration
  - nat troubleshoot
  - nat not working
  - nat broken
  - nat issue
  - nat problem
  - nat mismatch
  - source nat
  - destination nat
  - dnat
  - snat
  - static nat
  - bidirectional nat
  - dynamic ip and port
  - dipp
  - dipp pool
  - dipp exhaustion
  - nat pool exhaustion
  - port exhaustion nat
  - nat_dynamic_port_xlat_failed
  - nat oversubscription
  - show running ippool
  - no-nat
  - no nat
  - nat exemption
  - nat bypass
  - nat exclusion
  - vpn nat
  - nat vpn
  - vpn no-nat
  - vpn no nat
  - nat across vpn
  - site-to-site nat
  - ipsec nat
  - vpn source nat
  - vpn traffic nat
  - nat blocking vpn
  - nat tunnel
  - tunnel nat
  - internet nat vpn
  - u-turn nat
  - u turn nat
  - uturn nat
  - hairpin nat
  - hairpin
  - internal server public ip
  - internal server public fqdn
  - access server by public ip
  - loopback nat
  - internal to public fqdn
  - inbound nat
  - inbound dnat
  - dmz nat
  - dmz server nat
  - nat to dmz
  - public to dmz
  - destination nat dmz
  - nat zone dmz
  - pre-nat zone
  - post-nat zone
  - pre nat zone
  - post nat zone
  - pre-nat
  - post-nat
  - nat zone
  - nat destination zone
  - untrust to dmz nat
  - nat security rule zone
  - outbound nat
  - internet nat
  - egress nat
  - active active nat
  - active/active nat
  - ha nat
  - nat ha
  - nat failover
  - nat binding
  - device binding nat
  - asymmetric nat
  - ha nat asymmetric
  - test nat-policy-match
  - nat-policy-match
  - nat policy match
  - show running nat-policy
  - proxy arp nat
  - nat proxy arp
  - dns rewrite nat
  - nat dns rewrite
  - split dns nat
  - dns nat
  - pcnse nat
  - nat pcnse
  - kb-pan-nat
  - kb-pan-nat-001
---
# KB: NAT on Palo Alto Networks NGFW — VPN, U-Turn, Policy Zones, and Destination NAT

**Article ID:** KB-PAN-NAT-001
**Revision:** 2.0 — Consolidated

| Field | Value |
|-------|-------|
| **Article Owner** | Network Security Engineering |
| **Primary Platform** | Palo Alto Networks NGFW / PAN-OS / Panorama |
| **Applies To** | PAN-OS 10.0 / 10.1 / 10.2 / 11.0 / 11.1 / 11.2; Active/Passive and Active/Active HA |
| **Audience** | Firewall engineers, NOC/SOC escalation, PCNSE candidates, network architects |
| **Severity** | P1 (production traffic blackholed), P2 (specific app broken), P3 (intermittent / asymmetric) |
| **Last Reviewed** | May 10, 2026 |

> **Engineer summary:** Most NAT incidents come from one logical mistake — the engineer configures the rule using where the packet *should end up* instead of where the firewall *sees the original packet first*. In PAN-OS, NAT policy matching uses original packet addresses and zones determined by route lookup against the original destination. Security policy uses original pre-NAT addresses but post-NAT zones. Internalizing that single distinction prevents most VPN, U-turn, and destination NAT failures.

> **Core operational rule:** A NAT rule does not permit traffic. It only translates addresses and ports. The matching security policy must still allow the session. Treat NAT and security policy as two linked but separate decisions.

---

## Contents

1. Problem Statement and Scope
2. The Two Rules You Must Internalize
3. First-Principles NAT Model in PAN-OS
4. NAT Types — Quick Reference
5. Root-Cause Matrix
6. Incident Triage Workflow
7. VPN and NAT Interaction
8. U-Turn / Hairpin NAT
9. Destination NAT for Inbound DMZ Services
10. Source NAT, No-NAT, and Rule Order
11. Active/Active HA and Asymmetric NAT
12. DNS Rewrite and Split DNS Design
13. Pre-NAT / Post-NAT Reference Card
14. Troubleshooting Commands and Log Fields
15. Known Traps and Exact Fixes
16. Recommended NAT Policy Structure
17. NAT and the BPA / Best Practices
18. Change-Control Checklist
19. Escalation Bundle
20. PCNSE-Style Quick Answer Key
21. References
22. Revision History

---

## 1. Problem Statement and Scope

NAT bugs on Palo Alto firewalls almost never look like NAT bugs. They look like:

- "VPN tunnel is up but traffic doesn't pass"
- "Users can't reach our own website by its public name from the office"
- "The web server in the DMZ is unreachable from the internet — but the policy allows it"
- "Random sessions drop after Active/Active failover"
- "We're running out of source ports under load"

The failure is often indirect. The traffic may match a security rule, the route may look correct, and the tunnel may be up — but the firewall still translates the wrong address, skips the intended rule, or evaluates the policy against a zone the engineer did not expect.

This article covers the recurring production and PCNSE-style NAT failure patterns:

- Internet source NAT rules accidentally translating site-to-site VPN or GlobalProtect traffic
- U-turn or hairpin NAT for internal users who access an internal service by its public FQDN or IP
- Destination NAT for inbound DMZ services where the NAT rule and security rule use different destination zones
- Pre-NAT address vs. post-NAT zone confusion in both NAT policy and security policy
- Asymmetric NAT and device-specific NAT behavior in active/active HA
- No-NAT exemption placement, split DNS, DNS rewrite, and DIPP pool exhaustion

You should leave this article able to:

1. Recite the pre-NAT/post-NAT zone rule from memory and apply it under pressure
2. Configure inbound DNAT, U-turn NAT, and VPN-aware source NAT correctly the first time
3. Diagnose a NAT issue from `show session` and `test nat-policy-match` in under five minutes
4. Avoid the asymmetric-NAT trap in HA Active/Active

---

## 2. The Two Rules You Must Internalize

Every NAT mistake on PAN-OS comes from violating one of these. Print this. Tape it to your monitor.

### Rule 1 — NAT policy uses pre-NAT everything

When you write a NAT rule:

- **Source Zone** = the zone the packet came from (no translation has happened yet)
- **Destination Zone** = the zone the firewall *would* route the packet to **before any translation** — determined by route lookup against the original destination IP
- **Source IP** = pre-NAT (the original source)
- **Destination IP** = pre-NAT (the public IP, the typed-in IP, the originally-resolved IP)

For inbound DNAT, that public IP routes to the Untrust interface — so the destination zone in the NAT rule is **Untrust**, not DMZ. This is the #1 inbound DNAT configuration mistake.

### Rule 2 — Security policy uses pre-NAT IPs and post-NAT zones

When you write the matching security rule:

- **Source Zone** = pre-NAT (same as the NAT rule's source zone)
- **Source IP** = pre-NAT (the original source, even if you source-NAT it later)
- **Destination Zone** = **POST-NAT** (where the packet actually goes after destination translation)
- **Destination IP** = **PRE-NAT** (the original public IP, NOT the translated DMZ IP) ← this is the trap

For an inbound DNAT to a DMZ server:

| Field | NAT Rule | Security Rule |
|-------|----------|---------------|
| Source Zone | Untrust | Untrust |
| Destination Zone | **Untrust** *(pre-NAT — route lookup to public IP)* | **DMZ** *(post-NAT — where server actually lives)* |
| Destination IP | 203.0.113.10 *(public, pre-NAT)* | 203.0.113.10 *(still public, pre-NAT — never changes)* |

Engineers get the destination zone right on the security rule (DMZ) and then "fix" the destination IP to the private DMZ address. That's wrong, and it's the most common failed PCNSE scenario. The destination IP **never changes** in policy match logic — it always stays the pre-NAT original.

> **Memory anchor:** NAT rule = original addresses + original route-to zone. Security rule = original addresses + final destination zone. One rule solves most destination NAT and U-turn NAT questions.

---

## 3. First-Principles NAT Model in PAN-OS

The fundamental unit is a packet. A packet arrives with an original source IP, original destination IP, protocol, and port. The firewall makes two separate decisions: whether to translate addresses, and whether to allow the session. These use different information.

### The deterministic PAN-OS processing order

```
1.  Packet arrives → ingress interface → ingress (source) zone determined
2.  Route lookup on ORIGINAL destination IP → egress interface and egress zone determined (pre-NAT)
3.  NAT POLICY EVALUATION — top-down, first match wins
        Uses: ingress zone + pre-NAT egress zone + pre-NAT source IP + pre-NAT destination IP
4.  If destination NAT matched → destination IP translated
5.  SECOND route lookup on NEW (post-DNAT) destination IP → real egress zone (post-NAT)
6.  SECURITY POLICY EVALUATION
        Uses: ingress zone + POST-NAT egress zone + pre-NAT source IP + pre-NAT destination IP
7.  If security policy permits → source NAT applied (if matched in step 3)
8.  Packet egresses with translated addresses
9.  Session table records original + translated tuple for return-traffic matching
```

A single mistake in NAT zone direction cascades: the second route lookup happens only if the first one finds a route. If your route table sends the public IP somewhere unexpected, the egress zone for NAT lookup is wrong and nothing matches.

### Decision-point reference

| Decision Point | Uses Pre-NAT or Post-NAT? | Practical Meaning |
|---|---|---|
| NAT source address match | Pre-NAT source IP | Use the real client/server IP before any translation |
| NAT destination address match | Pre-NAT destination IP | Use the public/VIP/original destination the client actually sent to |
| NAT destination zone match | Zone from route lookup to the pre-NAT destination | For inbound DNAT to DMZ server, this is often Untrust, not DMZ |
| Security policy source address | Pre-NAT source IP | Use the real client IP before NAT |
| Security policy destination address | Pre-NAT destination IP | For inbound DNAT, use the public IP object, not the private DMZ server object |
| Security policy destination zone | Post-NAT destination zone | For inbound DNAT to a DMZ server, use DMZ |
| Traffic log NAT Source IP | Post-source-NAT IP | Use this to prove whether the session was source-translated [S12] |
| Traffic log NAT Destination IP | Post-destination-NAT IP | Use this to prove whether DNAT hit [S12] |

### Eight rules engineers must memorize

| Rule | Exact Statement | Reason |
|---|---|---|
| 1 | NAT rules are top-down and first-match | A broad internet NAT rule above a VPN no-NAT rule will translate VPN traffic before the exemption can ever be evaluated [S1] |
| 2 | NAT policy uses original packet addresses | For DNAT, the NAT destination is the public/VIP address, not the private server [S2] |
| 3 | NAT policy destination zone is based on route lookup to the original destination | For inbound DNAT to a DMZ host, the NAT destination zone is commonly Untrust because the original destination is public [S2] |
| 4 | Security policy uses original destination address but post-NAT destination zone | For inbound DNAT, the security rule is Untrust to DMZ, destination = public IP [S2] |
| 5 | No-NAT exemptions must be above general NAT rules | PAN-OS processes NAT top-down; once a broad rule matches, later no-NAT rules are irrelevant [S7] |
| 6 | U-turn NAT is destination NAT from Trust to Untrust when the original destination is public | The client is internal, but the original route lookup is toward the public IP [S5][S6] |
| 7 | Source NAT may be required in U-turn if the return path would bypass the firewall | Without it, the server replies to the original client IP via a direct path, bypassing the firewall — the client receives a response from a private IP it never contacted |
| 8 | Active/active HA NAT rules may require device binding | NAT rules are evaluated based on the session owner device; a firewall skips NAT rules not bound to it [S9] |

---

## 4. NAT Types — Quick Reference

| Type | Used For | Notes |
|------|----------|-------|
| **Dynamic IP and Port (DIPP)** | Outbound user → internet (most common SNAT) | Many-to-one with port translation; ~64k ports per public IP per destination tuple without oversubscription [S3] |
| **Dynamic IP** | Outbound where app needs unique source IP per session | One-to-one mapping from a pool; uses more public IPs but eliminates port collision |
| **Static IP** | Always-same translation for servers calling out | Often paired with DNAT for full bidirectional; must still be ordered above DIPP |
| **Destination NAT — Static** | Inbound DNAT: public IP → private server | Most common DMZ pattern [S4] |
| **Destination NAT — Dynamic** | Inbound to a pool (load distribution) | PAN-OS 8.1+; rarely the right answer — use a real load balancer |
| **Bidirectional NAT** | Static one-to-one in both directions | Auto-creates reverse rule; convenient but creates implicit rules that are hard to audit [S5] |
| **U-turn / Hairpin** | Internal users reaching internal servers via public FQDN | Requires destination NAT plus source NAT when return path could bypass firewall [S6] |
| **NAT64 / NAT46** | IPv6 ↔ IPv4 translation | Niche; PAN-OS supports both directions |
| **No-NAT** | Explicit exemption from translation | Not a special feature — it is a NAT rule whose translation action is None; position above broad rules is mandatory [S7] |

---

## 5. Root-Cause Matrix

| Symptom | Likely Cause | What to Verify | Fix |
|---|---|---|---|
| VPN tunnel is up; remote site sees firewall's public NAT address instead of internal subnet | Internet source NAT rule matched VPN traffic | Traffic log NAT Source IP; NAT rule hit count; NAT policy match test with local-to-remote subnets | Create no-NAT exemption above internet NAT matching local protected subnet to remote protected subnet and VPN/tunnel destination zone |
| VPN Phase 2 / proxy ID does not pass traffic after NAT change | NAT changed source/destination so encrypted-domain selectors no longer match | Proxy IDs, traffic selectors, NAT result, route to tunnel | Exempt VPN traffic from source NAT unless intentionally NATing across VPN and both sides agree on selectors |
| Internal user cannot reach internal server by public FQDN | Missing U-turn DNAT, wrong destination zone, or missing source NAT for hairpin return path | DNS result, NAT policy match Trust→Untrust→public IP, security rule Trust→DMZ, return path | Add U-turn DNAT; add source NAT if server could reply directly or same-zone path causes asymmetry |
| Inbound DMZ service does not work; logs show deny or no NAT match | NAT destination zone set to DMZ instead of Untrust | `test nat-policy-match` with source zone Untrust and destination zone Untrust to public IP | Set NAT Original Packet destination zone to pre-NAT route zone (Untrust); security rule destination zone to DMZ |
| Security rule never matches inbound DNAT | Security rule destination address set to private DMZ IP instead of public IP | Traffic log original destination and NAT Destination IP fields | Use pre-NAT public destination address in security policy destination field |
| Some HA active/active sessions NAT differently on peer devices | NAT rule binding/session owner mismatch or asymmetric path | Session owner, setup device, NAT binding tab, HA2 sync health | Bind NAT rules to correct device owners or use floating/shared design; ensure HA2 and routing symmetry |
| Public-facing server receives inbound sessions but initiates outbound with private IP | Only DNAT exists; no source/static/bidirectional NAT for server-initiated outbound | Outbound session NAT Source IP field | Add static source NAT or carefully configured bidirectional static NAT for server-initiated flows [S5] |
| No-NAT rule exists but traffic still NATs | Rule is below a broad NAT rule, wrong zone, wrong original destination, or service mismatch | NAT policy match test and rule hit counters | Move no-NAT above broad NAT; use original packet fields; verify zone matches route lookup result |
| DIPP pool exhaustion under load | Too few public IPs or oversubscription not configured | Counter `nat_dynamic_port_xlat_failed`; `show running ippool` | Add public IPs to DIPP pool; enable DIPP oversubscription in Device → Setup → Session |

---

## 6. Incident Triage Workflow

Do not start by editing NAT policy. First prove the packet walk. NAT issues are deterministic — the fastest method is to identify exactly which rule matched and which tuple is installed in the session table.

### Minimum data to collect before touching anything

- [ ] Source IP and user, including whether it is LAN, GlobalProtect, site-to-site VPN, DMZ, or internet
- [ ] Destination FQDN and resolved IP at the time of the test (DNS answer matters)
- [ ] Protocol and destination port
- [ ] Ingress interface and source zone
- [ ] Expected egress interface and destination zone before NAT
- [ ] Expected post-NAT source and destination IPs
- [ ] Actual NAT rule matched and security rule matched
- [ ] Traffic log fields: Source, Destination, NAT Source IP, NAT Destination IP, From Zone, To Zone, Rule, Session End Reason
- [ ] Session ID and `show session id` output when possible

### Triage sequence

**Step 1 — Run NAT policy match for the hypothetical flow**

This is the first command for every NAT ticket. 80% of cases end here.

```
test nat-policy-match from <src-zone> to <dst-zone> source <src-ip> destination <dst-ip> protocol <6|17> destination-port <port>
```

Specific examples:

```
# Outbound internet user
test nat-policy-match protocol 6 from Trust to Untrust source 192.168.10.50 destination 8.8.8.8 destination-port 443

# Site-to-site VPN traffic (should match no-NAT)
test nat-policy-match protocol 6 from Trust to VPN source 192.168.10.50 destination 10.50.20.25 destination-port 443

# Inbound destination NAT from internet
test nat-policy-match protocol 6 from Untrust to Untrust source 198.51.100.50 destination 203.0.113.100 destination-port 443

# U-turn NAT from internal client to public IP
test nat-policy-match protocol 6 from Trust to Untrust source 192.168.10.50 destination 203.0.113.100 destination-port 443
```

If the matching rule is not the intended rule — **stop and fix that** before doing anything else.

**Step 2 — Inspect a real session**

```
show session all filter source <ip> destination <ip>
show session id <id>
```

Key fields to read in `show session id` output:

```
source: 10.50.10.20 [Trust]
destination: 8.8.8.8 [Untrust]
proto: 6
sport: 51234     dport: 443
nat-rule: outbound-internet          ← wrong rule = ordering problem
nat-source-translation: 203.0.113.5 / port 47023
nat-destination-translation: N/A
```

If `nat-rule` shows the wrong rule, you have a NAT policy ordering or scoping problem. If `nat-source-translation` shows a VPN-bound subnet IP instead of a public IP, you found the classic VPN-and-NAT trap (Section 7).

**Step 3 — Confirm security policy match after NAT**

```
test security-policy-match from <src-zone> to <post-nat-dst-zone> source <pre-nat-src-ip> destination <pre-nat-dst-ip> protocol <n> destination-port <n>
```

Use the **pre-NAT** destination IP (the original public IP for DNAT). Use the **post-NAT** destination zone. Zone is post-NAT; IP is pre-NAT.

**Step 4 — Validate route lookup to original destination**

```
test routing fib-lookup virtual-router <vr-name> ip <original-destination-ip>
```

This confirms which egress interface and zone the firewall determined during step 2 of the packet flow — the value that feeds the NAT rule's destination zone.

**Step 5 — Check proxy ARP (for inbound DNAT)**

For DNAT to a public IP not directly bound to a firewall interface, the firewall must answer ARP for that IP on the upstream segment. If proxy ARP isn't working, the upstream router never sends the packet to the firewall.

```
show arp all
debug device-server show proxy-arp        # shows what proxy-ARP entries are programmed
test arp gratuitous interface <iface> ip <public-ip>
```

Proxy ARP is automatic on PAN-OS when the NAT translation IP is in the same subnet as the firewall's interface. If it is in a different subnet (e.g., a routed /29 from the ISP), coordinate with upstream to route that block to the firewall's Untrust IP instead. [S1]

**Step 6 — Check global counters**

Run before and after reproducing the failure; look at the delta:

```
show counter global filter aspect nat delta yes
show counter global filter delta yes severity drop
```

NAT counters that matter:

| Counter | Meaning |
|---------|---------|
| `nat_dynamic_port_xlat_failed` | DIPP pool exhaustion — not enough ports or public IPs |
| `flow_policy_nat_land` | NAT created a land attack pattern (src = dst after translation) — blocked |
| `pkt_alloc_failure` | Resource exhaustion, often correlated with NAT pool issues |
| `flow_fwd_l3_noroute_nat` | After NAT, no route exists for the new destination — fix routing or translation IP |

**Step 7 — Check return path**

NAT can be correct on the outbound leg but fail because the reply bypasses the firewall or lands on the wrong HA peer. Confirm server default gateway, routing, and — for HA — which peer received the return packet.

**Step 8 — Packet capture (last resort, definitive)**

```
debug dataplane packet-diag set filter match source <ip> destination <ip>
debug dataplane packet-diag set filter on
debug dataplane packet-diag set capture stage receive file rx
debug dataplane packet-diag set capture stage transmit file tx
debug dataplane packet-diag set capture stage drop file drop
debug dataplane packet-diag set capture on
# reproduce
debug dataplane packet-diag set capture off
debug dataplane packet-diag clear filter-marked-session all
```

Files land in `/var/tmp/`. The `drop` stage is usually the most useful — it shows exactly where and why the firewall discarded the packet.

> **Operational standard:** Every NAT ticket should end with a before/after packet walk. If the engineer cannot state: original source, original destination, pre-NAT route-to zone, matching NAT rule, translated tuple, matching security rule, and return path — the issue is not fully diagnosed.

---

## 7. VPN and NAT Interaction

### 7.1 Why internet NAT accidentally matches VPN traffic

The trap is a too-broad internet source NAT rule. A typical rule: source zone Trust, destination zone Any or Untrust, source = internal subnet, destination = Any, source translation = egress interface DIPP. That is safe only if VPN-protected destinations are in a different zone from Untrust — and they often aren't. Route-based VPN tunnel interfaces are frequently placed in Untrust. When the route lookup for a remote VPN subnet resolves to a tunnel interface in Untrust, the broad internet NAT rule matches before any VPN exemption can fire.

The result is one of four failures:

- Remote side receives traffic from the firewall's public IP instead of the local protected subnet
- IPsec proxy IDs or traffic selectors no longer match the intended encrypted domains — Phase 2 re-keys but traffic doesn't flow
- Return traffic goes to an unexpected translated address and never returns through the tunnel
- Security policy appears correct, but the actual session tuple is wrong after source NAT

### 7.2 Correct site-to-site VPN no-NAT pattern

| Rule Order | NAT Rule Name | Original Packet Match | Translated Packet Action | Purpose |
|---|---|---|---|---|
| 1 | NO-NAT-LAN-to-VPN | Source zone: Trust; Destination zone: VPN/Tunnel zone; Source: local protected subnets; Destination: remote protected subnets; Service: Any or required ports | Source Translation: None; Destination Translation: None | Prevents internet NAT from touching VPN traffic. Must be above all broad outbound NAT rules |
| 2 | SNAT-LAN-to-Internet | Source zone: Trust; Destination zone: Untrust; Source: internal subnets; Destination: Any or internet-only object/category | Dynamic IP and Port to egress interface or public pool | Allows normal internet egress translation |

### 7.3 VPN NAT design checklist

- **Use explicit remote subnet objects.** Do not rely on destination Any for VPN no-NAT rules.
- **Use the correct destination zone.** For route-based VPN, this is usually the tunnel interface zone, which may or may not be Untrust. Verify with `test routing fib-lookup`.
- **Place no-NAT first.** PAN-OS processes NAT top-down; the first matching rule wins. [S1][S7]
- **Mirror selectors.** Confirm both VPN peers expect the same local and remote subnets. If you intentionally NAT across VPN, both peer selectors and routing must account for the translated subnet.
- **Check GlobalProtect separately.** Remote-access VPN users may need source NAT to internet but no NAT to internal zones, depending on split-tunnel design.
- **Do not hide VPN clients unintentionally.** A broad GP-to-Any SNAT rule causes all internal servers to see the firewall IP instead of the real VPN pool IP — breaking logging, ACLs, and User-ID identity mapping.

### 7.4 Symptoms that prove VPN traffic is being NATed

- Traffic log NAT Source IP is populated for flows that should remain untranslated across the tunnel
- Remote firewall logs show the peer's public IP or translated pool instead of the expected local protected subnet
- Tunnel counters increment but application fails because the far side drops the unexpected source address
- `test nat-policy-match` returns the general internet DIPP rule instead of the VPN no-NAT rule
- Packet capture on the remote peer shows packets arriving from the wrong source network

### 7.5 Fix procedure for accidental VPN NAT

1. Identify the local and remote protected subnets from the VPN design or proxy ID configuration
2. Identify the actual source zone and destination zone after route lookup to the remote subnet (`test routing fib-lookup`)
3. Create or correct a no-NAT rule above all broad source NAT rules
4. Set Source Translation to None and Destination Translation to None
5. Commit and test with a single known flow
6. Confirm Traffic logs show blank NAT Source IP and blank NAT Destination IP for the VPN flow
7. Confirm the remote peer sees the original local protected source IP
8. Document the rule as a VPN NAT exemption and protect its rule order in change control

---

## 8. U-Turn / Hairpin NAT

### 8.1 What U-turn NAT is

U-turn NAT is required when an internal client tries to reach an internal or DMZ service using its public IP or public FQDN. The client source is internal, but DNS resolves the destination to the public address. PAN-OS routes the packet toward Untrust based on the original public destination address, then translates the destination to the server's private address. [S5][S6]

### 8.2 The correct U-turn packet walk

| Stage | Value in Common Design |
|-------|------------------------|
| Client sends | Source 192.168.10.50, destination 203.0.113.11, TCP/443 |
| Ingress zone | Trust |
| Initial route lookup to original destination | 203.0.113.11 routes toward Untrust |
| NAT rule Original Packet | Source zone Trust, destination zone Untrust, source = internal clients, destination = public IP 203.0.113.11, service tcp/443 |
| NAT translation | Destination → DMZ/private server IP 10.1.1.11. Source → firewall DMZ interface IP (if return path requires it) |
| Security policy | Source zone Trust, destination zone DMZ, source = internal client, destination = public IP 203.0.113.11 |
| Egress | Packet leaves toward DMZ server with destination 10.1.1.11. Server sees firewall/source-NAT address if source NAT is used |
| Return | Server reply must return through firewall to be un-NATed back to the client |

### 8.3 When U-turn needs source NAT too

Destination NAT changes the destination from the public IP to the private server IP. That alone does not guarantee a symmetric return path. Source NAT is required when the server could reply directly to the client instead of back through the firewall.

| Topology | Need Source NAT? | Why |
|----------|-----------------|-----|
| Client and server in different firewall zones; server default gateway is the firewall | Often no | Return traffic naturally returns to the firewall |
| Client and server in same subnet or same L2 segment | Usually yes | Server can ARP/reply directly to client, bypassing firewall. Client sent to public IP but receives response from private IP — session fails |
| Server has a different default gateway or asymmetric route | Usually yes, or fix routing | Return traffic may bypass firewall or arrive on a different path |
| Load balancer or reverse proxy in path | Depends | Verify whether return path is through the firewall and whether the proxy preserves the original client source |

### 8.4 U-turn NAT rule template

| Field | Recommended Value |
|-------|-------------------|
| Name | DNAT-Uturn-Internal-to-Public-Web |
| Original Packet Source Zone | Trust or internal client zone |
| Original Packet Destination Zone | Untrust — where route lookup for the public IP points. **This is the most common mistake.** |
| Original Packet Source Address | Internal client subnets that need public-FQDN access |
| Original Packet Destination Address | Public/VIP address of the service |
| Service | Original destination port (e.g., tcp/443) |
| Translated Packet Destination | Private server IP in DMZ or internal zone |
| Translated Packet Source | None unless return-path symmetry requires it. If required, translate to firewall DMZ interface IP or a pool the server can route back to |
| Matching Security Rule | Trust to DMZ (post-NAT zone), destination address = public/VIP IP (pre-NAT) |

### 8.5 Preferred alternative: split DNS

Split DNS is almost always cleaner than U-turn NAT. Internal DNS returns the private server IP to internal clients; public DNS returns the public IP to internet clients. This removes the need for internal clients to hairpin through public NAT and avoids hiding client IPs from the server.

When split DNS is not available, PAN-OS destination NAT with DNS rewrite can rewrite DNS responses associated with static destination NAT rules so the client receives an address appropriate to its network side. DNS rewrite follows NAT rule matching order, and forward/reverse direction must be selected based on topology. [S8]

---

## 9. Destination NAT for Inbound DMZ Services

### 9.1 The PCNSE trap

Inbound destination NAT to a DMZ server creates the most common zone-direction mistake. The engineer knows the real server is in DMZ, so they put destination zone DMZ in the NAT rule. That is wrong in the common one-to-one public IP design. NAT matching happens before the destination is translated. The initial route lookup is performed against the original public destination IP — which points to Untrust, not DMZ. Palo Alto documentation explicitly states that in a one-to-one destination NAT example, the destination NAT rule is from Untrust to Untrust; then the firewall translates the public IP to the private server IP and the security policy is evaluated from Untrust to DMZ. [S2]

### 9.2 Correct inbound DNAT configuration

| Component | Correct Value | Why |
|-----------|--------------|-----|
| Client | Internet host 198.51.100.50 | Original source stays as-is |
| Public service IP | 203.0.113.100 | Original destination in packet |
| Private server IP | 10.1.1.100 | Post-DNAT destination in DMZ |
| NAT rule source zone | Untrust | Traffic enters from internet |
| NAT rule destination zone | **Untrust** | Route lookup to original public IP points to external/untrust side |
| NAT rule destination address | 203.0.113.100 (public IP object) | NAT rules match original destination addresses |
| NAT translated destination | 10.1.1.100 (private server IP) | Destination translation target |
| Security policy source zone | Untrust | Ingress zone |
| Security policy destination zone | **DMZ** | Post-NAT zone where server physically lives |
| Security policy destination address | 203.0.113.100 (public IP object) | Security policy address field uses original pre-NAT destination |

### 9.3 Inbound DNAT failure patterns and fixes

| Failure | Cause | Fix |
|---------|-------|-----|
| NAT rule never hits | Destination zone set to DMZ instead of Untrust, wrong public IP object, missing proxy ARP, or service mismatch | Run `test nat-policy-match`. Set NAT destination zone to route-to zone for the public IP |
| NAT hits but security rule denies | Security policy destination zone set to Untrust, or destination address set to private server IP | Security policy should be Untrust to DMZ, destination = public IP object |
| Server receives session but replies out wrong gateway | Asymmetric return path from DMZ server | Fix server default gateway/routing; or add source NAT on inbound flow only if formally accepted |
| Firewall does not answer ARP for public NAT IP | Public IP is not in the firewall's connected subnet or proxy ARP not applicable due to topology | Ensure upstream routes public IP to firewall, or confirm IP is in connected external subnet and verify `debug device-server show proxy-arp` |
| Port translation works for one service but not another | Service object uses wrong original port, or security policy app/service mismatch | NAT service is the original destination port. Translated port goes on the Translated Packet tab. Security must allow the intended application/service |

### 9.4 Public-facing server outbound traffic

Destination NAT only handles inbound sessions initiated toward the public IP. If the same DMZ server initiates outbound sessions and must appear as its public IP, configure static source NAT or a carefully controlled bidirectional static NAT. Palo Alto documents bidirectional address translation for public-facing servers with both private and public-facing addresses. [S5]

> **Caution on bidirectional NAT:** Bidirectional NAT is convenient but creates implicit reverse rules that are harder to reason about in policy review. Many production teams prefer explicit inbound DNAT plus explicit outbound static SNAT so rule direction, hit counts, and change-control history remain unambiguous.

---

## 10. Source NAT, No-NAT, and Rule Order

Source NAT translates the source IP, most commonly for internal users accessing the internet. PAN-OS supports Static IP, Dynamic IP, and Dynamic IP and Port (DIPP) source NAT. DIPP allows multiple internal hosts to share one translated IP by using different source ports. [S3]

### 10.1 Recommended NAT policy order

| Position | Rule Type | Examples |
|----------|-----------|---------|
| 1 | Specific no-NAT exemptions | LAN-to-site-to-site VPN, GlobalProtect-to-internal, management subnets that must remain untranslated |
| 2 | Specific destination NAT | Inbound public IP to DMZ server; U-turn DNAT for internal clients |
| 3 | Specific static source NAT | DMZ server outbound static NAT; partner extranet NAT; overlapping VPN subnet NAT |
| 4 | Specific application/vendor NAT | SaaS partners requiring a known source NAT pool |
| 5 | General internet DIPP NAT | Trust/internal zones to Untrust/internet using interface address or egress public pool |
| 6 | Temporary or break-glass rules | Only with expiration date, logging, and change record |

### 10.2 No-NAT design rules

- No-NAT is not a special feature. It is a NAT policy rule whose translation action is None.
- No-NAT must be **above** rules that would otherwise translate the same flow. [S7]
- No-NAT must use original source and destination fields. For VPN, the destination is the remote protected subnet, not an abstract tunnel name.
- No-NAT destination zone must match the route lookup result for the original destination. For route-based VPN, this is usually the tunnel zone.
- No-NAT should be narrow enough that internet traffic still gets translated.

### 10.3 Rule-shadowing symptoms

- The intended NAT rule has zero hits while a broad rule above it increments
- `test nat-policy-match` returns a generic internet NAT rule for traffic that should be exempt
- Traffic log shows translated source for traffic that should not be translated
- Moving a rule above the internet NAT immediately changes behavior
- A service-specific NAT rule fails because the service field matches the wrong port

### 10.4 DIPP pool exhaustion

**Detection:** Counter `nat_dynamic_port_xlat_failed` increments under load. New sessions fail intermittently while established sessions are unaffected. Users report "internet mostly works but some connections fail."

**Fix:**
- Add public IPs to the DIPP pool — each additional IP adds ~64k additional port capacity
- Enable DIPP oversubscription: **Device → Setup → Session → NAT Oversubscription** (1x, 2x, 4x, 8x); higher values trade memory for capacity
- Carve out high-port-pressure flows (specific server-to-server, SaaS) to their own NAT rule using Dynamic IP instead of DIPP
- Verify: `show running ippool` shows current pool utilization; `show session info` shows total session counts

---

## 11. Active/Active HA and Asymmetric NAT

### 11.1 Why NAT is harder in active/active

In active/passive HA, one firewall is normally forwarding sessions, so NAT state is easier to reason about. In active/active HA, both firewalls forward traffic concurrently. A session can enter on one peer while the other peer receives the return. Palo Alto states that the session setup firewall performs the NAT policy match, but NAT rules are evaluated based on the session owner, and a firewall skips NAT rules not bound to the session owner device. [S9]

### 11.2 Common HA NAT failure modes

| Failure Mode | Technical Cause | Fix |
|---|---|---|
| Only sessions owned by one peer NAT correctly | NAT rule binding includes only one device ID, or translated pool exists only for one peer | Create correct device-specific NAT rules or use floating/shared translated addresses |
| Return traffic hits the other peer and is dropped | Asymmetric routing without proper session synchronization or HA3 forwarding | Verify HA2 health, session sync, HA3 forwarding, and routing symmetry |
| NAT pool differs by peer; remote systems see inconsistent source IPs | Each peer uses different source NAT pool without upstream/remote ACL awareness | Document peer-specific pools and update upstream ACLs; or use floating IP design |
| Failover works for existing sessions but new sessions use different NAT | Surviving peer uses only NAT rules matching its device ID for new sessions | Review active/active NAT binding and failover behavior [S9] |
| Troubleshooting from only one peer is misleading | Session owner or setup device may not be the CLI peer being checked | Check both peers, session owner, device ID, and session synchronization state |

### 11.3 Active/active NAT strategies

**Option A — HA3 packet forwarding (preferred):** Configure an HA3 link. When a peer receives a packet for a session owned by the other peer, it forwards over HA3 for processing. Makes asymmetric arrivals transparent, but HA3 link must be sized for the forwarded load (10G+ recommended).

```
Device → High Availability → Active/Active Config:
  Packet Forwarding: Enable
  HA3 Interface: <dedicated interface>
```

**Option B — Floating IPs for source NAT:** Use floating IP addresses owned by one device for SNAT. Both devices use the same floating IP for SNAT. Failover moves the floating IP. Loses the load-balancing benefit of A/A for those flows but eliminates the asymmetry problem.

**Option C — Device-ID NAT pools:** Configure DIPP pools per device ID. Combined with session ownership tied to device ID. Most complex; gives full A/A benefit; requires both public IPs to be routable from outside for return traffic.

```
NAT Rule "outbound-internet-fw1":
  Active/Active Device Binding: 0
  Source Translation: dynamic-ip-and-port → 203.0.113.5
NAT Rule "outbound-internet-fw2":
  Active/Active Device Binding: 1
  Source Translation: dynamic-ip-and-port → 203.0.113.6
```

### 11.4 HA troubleshooting checklist

- [ ] Identify session setup firewall and session owner (`show session id <id>` on both peers)
- [ ] Check NAT Active/Active HA Binding tab for the matching rule
- [ ] Confirm translated address ownership, floating IP binding, or upstream routing for each peer
- [ ] Confirm HA2 status — HA2 is responsible for session and forwarding table synchronization [S10]
- [ ] Verify whether return traffic lands on the same peer, the session owner, or a synchronized peer
- [ ] Run `test nat-policy-match` with the correct HA device ID where applicable
- [ ] Validate failover behavior for both existing sessions and new sessions

```
show high-availability state
show high-availability flap-statistics
show high-availability session-info
```

---

## 12. DNS Rewrite and Split DNS Design

NAT problems frequently start with DNS. If an internal client resolves an internal server to a public IP, traffic follows the public-IP routing logic unless split DNS, DNS rewrite, or U-turn NAT handles it.

| Design Option | Best Use | Strength | Risk / Limitation |
|---|---|---|---|
| Split DNS | Internal users accessing internal services by the same public FQDN | Simple packet flow; avoids hairpin NAT; server sees real client IP | Requires control over DNS architecture (internal DNS zone for the FQDN) |
| U-turn NAT | Internal users must use public DNS and DNS cannot be changed | Works without changing DNS | More complex policy; requires source NAT; hides client IP from server |
| DNS Rewrite | Static DNAT cases where the firewall can cleanly rewrite DNS responses | Can steer clients to correct address automatically | Direction and match logic are easy to misconfigure; not compatible with every NAT design [S8] |
| Public-only DNS with no U-turn | External-only services | Simple for internet users | Internal users will fail when trying to reach the internal resource by public IP |

PAN-OS destination NAT DNS rewrite modifies IPv4 addresses in DNS responses associated with static destination NAT rules. DNS rewrite follows NAT rule matching order, and forward/reverse direction must be chosen based on whether the DNS response should be translated in the same direction as the NAT rule or the opposite direction. [S8]

---

## 13. Pre-NAT / Post-NAT Reference Card

Cut this out. Tape it next to Section 2.

### Outbound source NAT (user → internet)

| Field | NAT Rule | Security Rule |
|-------|----------|---------------|
| Source Zone | Trust | Trust |
| Destination Zone | Untrust | Untrust |
| Source IP | 10.0.0.0/8 (pre-NAT) | 10.0.0.0/8 (pre-NAT) |
| Destination IP | any | any |
| Translation | DIPP → public IP | n/a |

### Inbound destination NAT (internet → DMZ server)

| Field | NAT Rule | Security Rule |
|-------|----------|---------------|
| Source Zone | Untrust | Untrust |
| Destination Zone | **Untrust** *(pre-NAT)* | **DMZ** *(post-NAT)* |
| Source IP | any | any |
| Destination IP | 203.0.113.10 (public, pre-NAT) | 203.0.113.10 (still public, pre-NAT — never changes) |
| Translation | dest IP → 192.168.10.5 | n/a |

### U-turn NAT (internal user → internal server via public FQDN)

| Field | NAT Rule | Security Rule |
|-------|----------|---------------|
| Source Zone | Trust | Trust |
| Destination Zone | **Untrust** *(pre-NAT — public IP routes to Untrust)* | **DMZ** *(post-NAT)* |
| Source IP | 10.0.0.0/8 | 10.0.0.0/8 |
| Destination IP | 203.0.113.10 (public, pre-NAT) | 203.0.113.10 (still public, pre-NAT) |
| Translation | src → FW DMZ interface IP; dest → 192.168.10.5 | n/a |

### Outbound to VPN remote subnet (no NAT)

| Field | NAT Rule (no-NAT) | Security Rule |
|-------|-------------------|---------------|
| Source Zone | Trust | Trust |
| Destination Zone | Tunnel zone or Untrust *(verify with route lookup)* | Same as NAT rule |
| Source IP | 10.0.0.0/8 | 10.0.0.0/8 |
| Destination IP | 192.168.50.0/24 (remote VPN subnet) | 192.168.50.0/24 |
| Translation | **None** | n/a |

---

## 14. Troubleshooting Commands and Log Fields

### 14.1 CLI reference

```
# NAT policy match — hypothetical flow
test nat-policy-match from <zone> to <zone> source <ip> destination <ip> protocol <6|17> destination-port <n>

# Security policy match — uses pre-NAT IPs, post-NAT zone
test security-policy-match from <zone> to <post-nat-zone> source <pre-nat-ip> destination <pre-nat-ip> protocol <n> destination-port <n>

# Route lookup to original destination (determines NAT rule's destination zone)
test routing fib-lookup virtual-router <vr-name> ip <destination-ip>

# Inspect all sessions or a specific session
show session all filter source <ip> destination <ip>
show session id <id>

# NAT-related global counters
show counter global filter aspect nat delta yes
show counter global filter delta yes severity drop

# Source NAT pool utilization
show running ippool
show running nat-rule-cache

# NAT rule hit counters (PAN-OS 9.0+)
show running nat-policy

# Proxy ARP programming
debug device-server show proxy-arp
show arp all

# HA active/active state
show high-availability state
show high-availability flap-statistics
show high-availability session-info

# 4-stage packet capture
debug dataplane packet-diag set filter match source <ip> destination <ip>
debug dataplane packet-diag set filter on
debug dataplane packet-diag set capture stage receive file rx
debug dataplane packet-diag set capture stage transmit file tx
debug dataplane packet-diag set capture stage drop file drop
debug dataplane packet-diag set capture on
# reproduce the failure
debug dataplane packet-diag set capture off
debug dataplane packet-diag clear filter-marked-session all
# retrieve: scp export filter-pcap from rx to <host>
```

### 14.2 Traffic log fields to add to your NAT troubleshooting view

| Field | Why It Matters |
|-------|---------------|
| Source Address | Original source IP before any NAT |
| Destination Address | Original destination IP before any NAT |
| NAT Source IP | Post-source-NAT IP if source NAT occurred. Confirms whether the session was source-translated [S12] |
| NAT Destination IP | Post-destination-NAT IP if DNAT occurred. Confirms whether DNAT hit and what the translated address was [S12] |
| From Zone | Ingress / source zone |
| To Zone | Destination zone used by security policy (post-NAT) |
| Ingress Interface | Confirms where the packet entered the firewall |
| Egress Interface | Confirms where the packet left after routing/NAT decision |
| Rule | Security policy rule matched |
| Session End Reason | Distinguishes policy-deny, aged-out, tcp-rst-from-client/server, resources-unavailable, incomplete |

---

## 15. Known Traps and Exact Fixes

| Trap | Wrong Assumption | Correct Logic | Fix |
|------|-----------------|---------------|-----|
| Inbound DNAT to DMZ | NAT destination zone should be DMZ because server is there | NAT destination zone follows route lookup to original public IP — usually Untrust. Security policy destination zone is DMZ [S2] | NAT: Untrust to Untrust, destination = public IP. Security: Untrust to DMZ, destination = public IP |
| U-turn NAT | NAT destination zone should be DMZ because translated server is in DMZ | Original public IP routes toward Untrust, so NAT rule is Trust to Untrust [S5][S6] | NAT: Trust to Untrust, dest = public IP → private server. Security: Trust to DMZ, destination = public IP |
| VPN no-NAT not working | A no-NAT rule works regardless of position | NAT is first-match. A broad rule above wins [S1][S7] | Move specific no-NAT above general internet NAT |
| Security destination address after DNAT | Use private server IP in security rule because traffic ends there | Security address fields use original pre-NAT addresses [S1][S2] | Use public IP object as destination address in inbound DNAT security policy |
| Static NAT order | Static NAT automatically overrides dynamic NAT | Static NAT has no special precedence — order matters [S1] | Place specific static NAT above broad dynamic NAT |
| Service field in NAT | Use translated port in Original Packet service field | Original Packet service is the original destination port as sent by the client | Match public/original port in NAT service; put translated port in Translated Packet section |
| Hairpin same subnet | DNAT alone is enough for U-turn | Server may ARP-reply directly to client, bypassing firewall | Add source NAT to force return through firewall, or redesign with split DNS |
| HA active/active NAT | Both peers evaluate all NAT rules the same way | NAT matching is tied to session owner and device binding [S9] | Check NAT binding, session owner, translated pool ownership, and HA2 health |
| No-NAT destination zone | Use tunnel name or any in destination zone | Must use the zone the route lookup resolves to for the original destination | Verify with `test routing fib-lookup` and set the correct zone in the no-NAT rule |
| Bidirectional NAT review | Bidirectional is transparent and easy to audit | Bidirectional creates implicit reverse rules not visible in the forward NAT rule list | Use explicit inbound DNAT + explicit outbound static SNAT in production |

---

## 16. Recommended NAT Policy Structure

For a typical enterprise edge with internet egress, VPN partners, GlobalProtect, DMZ services, and HA:

```
1.   no-nat-internal-to-internal       # Trust → Trust (intra-zone)
2.   no-nat-vpn-partners               # Trust → Tunnel zone, dst = VPN remote subnets
3.   no-nat-vpn-clients                # GlobalProtect zone → DMZ/Trust
4.   dnat-web-prod                     # Untrust → Untrust → DMZ web farm
5.   dnat-mail-relay                   # Untrust → Untrust → DMZ mail
6.   dnat-vpn-portal                   # Untrust → Untrust → GP portal
7.   u-turn-www-company-com            # Trust → Untrust → DMZ (src NAT to interface)
8.   snat-mail-relay-out               # DMZ → Untrust, specific source, static translation
9.   snat-dns-resolver-out             # DMZ → Untrust, specific source
10.  outbound-internet                 # Trust/DMZ → Untrust, DIPP catch-all
```

**Rules of thumb:**

- Always lead with no-NAT rules
- Group by direction: no-NAT → inbound DNAT → static SNAT → catch-all DIPP
- Use address objects and groups, not literal IPs — refactoring later is much easier
- Tag every NAT rule with its purpose: `inbound-dnat`, `outbound-snat`, `vpn-bypass` — the Panorama tag-based rule view becomes navigable at scale
- Document the rationale in the **Description** field — future-you will not remember why rule #7 has source NAT to interface instead of a pool

---

## 17. NAT and the BPA / Best Practices

The Best Practice Assessment flags:

- Bidirectional NAT used where explicit rules would be clearer (implicit reverse rules are hard to audit)
- NAT rules without descriptions
- Disabled NAT rules left in policy (clutter and confusion at change time)
- Source NAT to interface address (acceptable for U-turn; should be flagged for review elsewhere)
- Overlapping NAT translation pools

Run BPA quarterly against any NAT policy with more than 20 rules. It catches shadowing, pool overlap, and missing documentation that humans overlook during reviews.

---

## 18. Change-Control Checklist

Use this before approving any NAT change in a production environment.

| Check | Question | Pass Condition |
|-------|----------|----------------|
| Packet walk | Can the engineer state original source, original destination, route-to zone, NAT rule, translated tuple, security rule, and return path? | All values known and documented |
| Rule order | Is any broad rule above the new specific rule? | Specific no-NAT/DNAT/static rules are above broad internet NAT |
| VPN exemption | Could this rule match VPN-protected subnets? | VPN no-NAT tested and confirmed above broad NAT |
| Destination NAT zones | For inbound DNAT, does NAT use pre-NAT route zone and security use post-NAT server zone? | NAT and security policy use intentionally different destination zones |
| Address objects | Are NAT and security policies using public/private address objects correctly? | DNAT NAT destination and security destination use original public IP; translation target uses private IP |
| Service/port | Is the original service matched correctly? Is translated port configured only where needed? | Original packet service = client destination port |
| Return path | Will replies return through the same firewall/session path? | Routing, gateways, HA behavior, and source NAT requirement all validated |
| Logging | Will affected security rules log at session end? | Logs show original and NAT addresses |
| Rollback | Is there a specific rollback plan? | Previous rule order and config snapshot available |
| Testing | Has NAT policy match been run for both positive and negative cases? | Expected flows hit intended rule; excluded flows do not |

---

## 19. Escalation Bundle

Escalate NAT incidents with evidence. A senior engineer or vendor TAC cannot solve a NAT problem from a description like "the NAT is not working." Include the packet walk and proof points.

**Collect before opening a case:**

- [ ] Firewall model, PAN-OS version (`show system info | match version`), HA mode, Panorama/device group context
- [ ] Tech support file: **Device → Support → Generate Tech Support File**
- [ ] Source IP, source zone, destination IP/FQDN, pre-NAT destination zone, protocol, port
- [ ] NAT rule name expected vs. NAT rule name actually matched
- [ ] Security rule name expected vs. security rule name actually matched
- [ ] Traffic log entry with NAT Source IP and NAT Destination IP fields visible
- [ ] `show session id` output for the failing session
- [ ] Route lookup to original destination and (for DNAT) route lookup to translated destination
- [ ] Output of `show counter global filter aspect nat delta yes` before and after reproduction
- [ ] Packet captures with all four stages (`receive`, `transmit`, `firewall`, `drop`) covering a reproducible failure
- [ ] For VPN: proxy IDs/traffic selectors, route to tunnel, tunnel zone, and peer-side logs
- [ ] For U-turn: DNS answer, U-turn NAT rule config, source NAT decision, server default gateway/return path
- [ ] For HA active/active: session owner, setup device, NAT binding, HA2 status, outputs from **both** peers
- [ ] Recent NAT/security/routing/HA changes and rollback option

"NAT is broken" gets triaged to the bottom. "NAT rule X matches when I expect rule Y, here is the test output and session table" gets a senior engineer on the first exchange.

---

## 20. PCNSE-Style Quick Answer Key

| Question Pattern | Correct Answer |
|---|---|
| Inbound user from internet accesses public IP that DNATs to DMZ server. What is the NAT rule destination zone? | Untrust — the route lookup to the original public destination points to the untrust/external side |
| Same scenario: what is the security rule destination zone? | DMZ — security policy uses post-NAT destination zone |
| Same scenario: what destination address goes in the security rule? | The original public IP object, not the private DMZ server IP |
| Internal user accesses internal DMZ server by public FQDN. What NAT rule direction? | Trust to Untrust in the NAT rule — original destination is public and routes toward Untrust; translate destination to private server |
| Why is source NAT sometimes added to U-turn NAT? | To force the server return path back through the firewall and prevent direct private-IP replies to the client |
| VPN tunnel is up but remote side sees firewall public IP. What happened? | General internet source NAT matched VPN traffic. Add a no-NAT exemption above it |
| Why did a no-NAT rule not work? | It was below a broader NAT rule, used the wrong destination zone, wrong original destination, or wrong service |
| Do static NAT rules automatically take precedence over dynamic NAT rules? | No. Static NAT rules need to be ordered above other NAT rules when required [S1] |
| In active/active HA, why does NAT differ by peer? | NAT evaluation can depend on session owner and device ID binding [S9] |
| What log fields prove NAT occurred? | NAT Source IP and NAT Destination IP in Traffic logs [S12] |
| What is the correct sequence: NAT match, then security match, or security match then NAT? | NAT policy is evaluated first (using pre-NAT everything), then security policy (using pre-NAT IPs and post-NAT zones) |

---

## 21. References

| ID | Reference | URL | Used For |
|----|-----------|-----|----------|
| S1 | Palo Alto Networks: NAT Policy Rules | https://docs.paloaltonetworks.com/ngfw/networking/nat/nat-policy-rules | NAT order, route lookup, pre-NAT addresses, post-NAT zones, static NAT ordering, no-NAT concept |
| S2 | Palo Alto Networks: Destination NAT Example — One-to-One Mapping | https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-networking-admin/nat/nat-configuration-examples/destination-nat-exampleone-to-one-mapping | Inbound DNAT zone direction and pre-NAT address behavior |
| S3 | Palo Alto Networks: Source NAT | https://docs.paloaltonetworks.com/ngfw/networking/nat/source-nat | Static IP, Dynamic IP, DIPP source NAT behavior |
| S4 | Palo Alto Networks: Destination NAT | https://docs.paloaltonetworks.com/ngfw/networking/nat/destination-nat | Static and dynamic destination NAT concepts |
| S5 | Palo Alto Networks: Configure NAT | https://docs.paloaltonetworks.com/ngfw/networking/nat/configure-nat | NAT examples including internet source NAT, U-turn NAT, bidirectional static source NAT |
| S6 | Palo Alto Networks: Enable Clients on the Internal Network to Access your Public Servers (Destination U-Turn NAT) | https://docs.paloaltonetworks.com/ngfw/networking/nat/configure-nat/enable-clients-on-the-internal-network-to-access-your-public-servers-destination-u-turn-nat | U-turn NAT behavior |
| S7 | Palo Alto Networks: Disable NAT for a Specific Host or Interface | https://docs.paloaltonetworks.com/ngfw/networking/nat/configure-nat/disable-nat-for-a-specific-host-or-interface | No-NAT/exemption placement before other NAT policies |
| S8 | Palo Alto Networks: Configure Destination NAT with DNS Rewrite | https://docs.paloaltonetworks.com/ngfw/networking/nat/configure-nat/configure-destination-nat-dns-rewrite | DNS rewrite logic, forward/reverse direction, NAT rule matching order |
| S9 | Palo Alto Networks: Set Up Active/Active HA | https://docs.paloaltonetworks.com/ngfw/administration/high-availability/set-up-activeactive-ha | Session owner, NAT rule binding, active/active NAT evaluation |
| S10 | Palo Alto Networks: HA Links and Backup Links | https://docs.paloaltonetworks.com/ngfw/administration/high-availability/ha-links-and-backup-links | HA2 synchronization of sessions, forwarding tables, IPSec SAs, ARP tables |
| S11 | Palo Alto Networks: Test Security Rules / NAT Policy Match | https://docs.paloaltonetworks.com/network-security/security-policy/administration/security-rules/test-policy-rule-traffic-matches | Policy match inputs and NAT match result via Device Troubleshooting |
| S12 | Palo Alto Networks: Traffic Log Fields | https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields | NAT Source IP and NAT Destination IP log-field definitions |
| — | Palo Alto Networks TechDocs: NAT Policies | https://docs.paloaltonetworks.com/pan-os/network-security/administration/policies/nat-policies | General NAT reference |
| — | BPA Tool | https://bpa.paloaltonetworks.com | Best Practice Assessment for NAT policy audit |
| — | CLI Quick Reference | https://docs.paloaltonetworks.com/pan-os/cli-quick-start | CLI syntax reference |

---

## 22. Revision History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-05-10 | Original — formal KB (DOCX): 17-section structured article with 12 cited references, root-cause matrix, PCNSE Q&A, change-control checklist, DNS rewrite comparison, traffic log field table, known-traps table |
| 1.1 | 2026-05-10 | Original — engineering KB (MD): CLI-focused article with numbered packet flow, NAT types table, proxy ARP CLI, global counters, 4-scenario reference card, DIPP exhaustion, recommended policy structure |
| 2.0 | 2026-05-10 | Merged — combined both sources; added DNS rewrite comparison table, PCNSE Q&A, change-control checklist, HA3 strategy options, 4-scenario reference card, DIPP oversubscription guidance, proxy ARP CLI, full counter table, 4-stage packet capture procedure, BPA section, complete CLI cheat sheet, 12 cited source references |

> **Document control note:** Review this article after major PAN-OS upgrades, HA topology changes, new VPN deployments, or NAT rulebase refactoring. NAT behavior is deterministic, but rulebases drift over time. The safest operational practice is to keep NAT rules narrow, ordered by specificity, and documented with the intended packet walk.
