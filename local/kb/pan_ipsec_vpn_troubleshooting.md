# KB: IPsec Site-to-Site VPN — Tunnel Up, Traffic Does Not Pass

**Article ID:** KB-PAN-VPN-001

| Field | Value |
|-------|-------|
| **Article Type** | Troubleshooting KB |
| **Primary Issue** | IPsec site-to-site tunnel is up, but traffic does not pass |
| **Most Frequent Causes** | Proxy-ID / traffic selector mismatch, routing error, NAT exemption failure, security policy block, MTU/MSS blackhole, PSK rotation, IKE version mismatch, PFS mismatch |
| **Primary Platforms** | Palo Alto Networks PAN-OS, Cisco ASA, Fortinet FortiGate, Microsoft Azure VPN Gateway |
| **Scope Note** | Addresses tunnels showing as active in the dashboard where production traffic is silently dropped. Does not cover IKE negotiation failures or certificate issues |
| **Last Updated** | May 2026 |

> **Core Principle:** A green VPN status proves that some control-plane negotiation succeeded. It does not prove that the actual application flow is matching the correct selector, route, NAT rule, security policy, or MTU path.

> **Diagnostic Rule:** Do not troubleshoot only the VPN status indicator. Troubleshoot a specific 5-tuple flow: source IP, destination IP, protocol, source port, and destination port.

---

## Contents

1. Issue Summary
2. Applies To
3. Fast Triage Logic
4. Common Symptoms
5. Root Cause 1 — Proxy-ID, Traffic Selector, or Crypto ACL Mismatch
6. Root Cause 2 — Routing Does Not Send Traffic Into the Tunnel
7. Root Cause 3 — Security Policy Blocks the Traffic
8. Root Cause 4 — NAT Breaks the Encryption Domain
9. Root Cause 5 — GRE, IPsec, MTU, MSS, and DF-Bit Blackholing
10. Root Cause 6 — PSK Rotation Problems
11. Root Cause 7 — IKEv1 vs. IKEv2 Negotiation Mismatch
12. Root Cause 8 — PFS Group Mismatch
13. Standard Troubleshooting Workflow
14. Platform Command Reference
15. Resolution Checklist
16. Escalation Data to Collect
17. References

---

## 1. Issue Summary

An IPsec site-to-site VPN tunnel shows as **up**, but production traffic does not pass across the tunnel. This symptom is common because the tunnel has independent control-plane and data-plane requirements. IKE Phase 1 and IPsec Phase 2 can be established while the actual packet flow still fails because the flow is not selected, routed, permitted, translated, or sized correctly.

### Minimum Technical Truths

- IKE Phase 1 establishes trust and key exchange between peers.
- IPsec Phase 2 establishes one or more security associations for matching traffic.
- Traffic must match the negotiated proxy ID, traffic selector, crypto ACL, or Phase 2 selector.
- Routing must send the packet toward the tunnel.
- Security policy must allow the flow.
- NAT must not alter the source or destination in a way that conflicts with the encryption domain unless NAT over VPN is intentionally designed.
- The final encapsulated packet must fit the effective path MTU, or fragmentation and PMTUD must work correctly.

---

## 2. Applies To

- Palo Alto Networks PAN-OS site-to-site IPsec VPNs (PAN-OS 11.x / Panorama)
- Cisco ASA site-to-site VPN peers
- Fortinet FortiGate IPsec peers
- Microsoft Azure VPN Gateway connections
- IKEv1 and IKEv2 tunnels
- Route-based and policy-based VPN designs
- GRE-over-IPsec or GRE adjacent to IPsec designs

---

## 3. Fast Triage Logic

| Observation | Most Likely Meaning | Next Check |
|---|---|---|
| Tunnel green, no packets pass | Control plane may be up but data-plane flow is not matching or not permitted | Check route, security policy, NAT, and selectors |
| Encaps increase, decaps do not | Local side sends encrypted traffic but peer or return path is failing | Check peer selector, peer routing, peer NAT, and return policy |
| Decaps increase, encaps do not | Peer sends traffic but local reply path does not enter tunnel | Check local route, NAT, and security policy |
| Only one subnet pair fails | Selector, route, policy, or NAT mismatch for that subnet pair | Compare exact local and remote selectors on both peers |
| Small packets pass, large packets fail | MTU, MSS, fragmentation, or DF-bit blackhole | Run DF-bit ping tests and inspect packet captures |
| Tunnel fails after rekey | Lifetime, PFS, proposal, or PSK mismatch | Compare Phase 2 crypto, PFS group, lifetime, and authentication |

---

## 4. Common Symptoms

| Symptom | Likely Technical Area | Severity |
|---|---|---|
| Tunnel flaps every 1–8 hours | Proxy-ID mismatch or PSK mismatch surfacing at SA re-key | HIGH |
| Small pings pass, large transfers stall | MTU / DF-bit drop | HIGH |
| Tunnel up, zero traffic in either direction | Missing security policy or route | HIGH |
| Traffic works in one direction only | Asymmetric routing or missing return policy | MEDIUM |
| VPN traffic is NATed to wrong IP | Missing NAT exemption rule | MEDIUM |
| Phase 2 fails after 1 hour (not initial) | PFS group mismatch | MEDIUM |
| Traffic logs show translated IPs unexpected by peer | NAT order or NAT exemption failure | MEDIUM |
| Azure tunnel: BGP routes not received | BGP not enabled or wrong AS on PAN side | INFO |
| IKE fails only after PSK change | PSK updated on one peer only | HIGH |

---

## 5. Root Cause 1 — Proxy-ID, Traffic Selector, or Crypto ACL Mismatch

This is the **most frequent cause** when a tunnel is up but traffic does not pass, especially with non-Palo Alto peers such as Cisco ASA, Fortinet FortiGate, and Azure VPN Gateway.

IPsec does not automatically encrypt every possible packet. It encrypts traffic that matches an agreed **encryption domain**. When IKEv1 is in use, both peers must agree on an exact set of traffic selectors (Proxy-IDs) during Phase 2. Palo Alto's default behavior is to send `0.0.0.0/0 → 0.0.0.0/0`, which many non-PAN peers reject.

### Per-Peer Behavior and Failure Modes

| Platform | Common Term | Default Behavior | Failure Mode |
|---|---|---|---|
| **Palo Alto Networks** | Proxy ID / Traffic Selector | Sends `0.0.0.0/0 → 0.0.0.0/0` by default | Non-PAN peers may reject; SA installs but traffic not encrypted |
| **Cisco ASA** | Crypto ACL / interesting traffic | Sends/expects exact subnets from crypto map match address ACL | Phase 2 SA installs but PAN sends 0/0; ASA tears down SA with proxy-id mismatch; tunnel flaps every few minutes |
| **Fortinet FortiGate** | Phase 2 Selector | Derives selectors from source/destination address objects | Mismatch if PAN proxy-ID local/remote don't exactly mirror FortiGate selectors; traffic dropped without Phase 2 teardown in some firmware versions |
| **Azure VPN Gateway** | Traffic Selector / Policy-based Traffic Selector | Route-based (IKEv2, 0.0.0.0/0) by default; policy-based expects exact prefixes | Policy-based: PAN must send exact matching selectors. Route-based: works with 0/0 but BGP route advertisement may be missing |

### Fix on PAN-OS

Navigate to **Network → IPsec Tunnels → [tunnel] → Proxy IDs** and add an explicit entry per subnet pair. A single 'supernet' Proxy-ID that doesn't exactly match the peer's ACL will still cause a mismatch.

```
# CLI equivalent — set proxy-id to match far-end traffic selectors
set network tunnel ipsec TUNNEL-NAME proxy-id PROXY-NAME \
    local 10.10.0.0/24 \
    remote 192.168.100.0/24 \
    protocol any
```

### Selector Validity Matrix

| Side A Local | Side A Remote | Side B Local | Side B Remote | Valid? |
|---|---|---|---|---|
| 10.1.1.0/24 | 172.16.1.0/24 | 172.16.1.0/24 | 10.1.1.0/24 | ✅ Yes |
| 10.1.0.0/16 | 172.16.1.0/24 | 172.16.1.0/24 | 10.1.1.0/24 | ⚠️ Risky |
| 10.1.1.0/24 | 172.16.1.0/24 | 172.16.0.0/16 | 10.1.1.0/24 | ⚠️ Risky |

### Verification

```
# Show active IKE Phase 2 SAs and their negotiated selectors
show vpn ipsec-sa

# Check for proxy-id mismatch in system logs
show log system direction equal forward subtype equal vpn

# Cisco ASA
show crypto ikev1 sa
show crypto ikev2 sa
show crypto ipsec sa
show access-list
show nat
packet-tracer input inside tcp <src-ip> <src-port> <dst-ip> <dst-port>

# FortiGate
get vpn ipsec tunnel summary
diagnose vpn tunnel list
diagnose debug reset
diagnose debug application ike -1
diagnose debug enable
```

Look for `ike-nego-p2-fail` or `proxy-id mismatch` in the system log. On Cisco ASA, `debug crypto isakmp 255` will show **"Rejecting IPSec tunnel: no matching crypto map entry"** if selectors differ.

---

## 6. Root Cause 2 — Routing Does Not Send Traffic Into the Tunnel

A route-based VPN still requires the routing table to point the remote network toward the tunnel interface. A policy-based peer still requires the traffic to reach the VPN decision process. If routing sends the packet to the internet interface, a default route, or a different virtual router, the tunnel status does not matter.

### Symptoms

- Encapsulation counters do not increase
- Traffic logs show egress through an internet or internal interface instead of the tunnel zone
- Only directly connected or default-routed traffic fails
- Return traffic never appears on the local firewall

### PAN-OS Checks

```
show routing route destination <remote-ip>
show routing fib lookup virtual-router <vr-name> ip <remote-ip>
show vpn flow
show vpn ipsec-sa tunnel <tunnel-name>

# Confirm route to remote subnet resolves through tunnel
test routing fib-lookup virtual-router default ip 192.168.100.5
```

### Fix

Create a static route: **Destination = remote subnet, Interface = tunnel.x, Next hop = none** (unless design requires it), Virtual router = correct VR.

Also confirm the source and destination zones used by security policy. On Palo Alto Networks firewalls, route-based VPNs often use a dedicated **tunnel zone**, so security policy must reference that zone correctly.

---

## 7. Root Cause 3 — Security Policy Blocks the Traffic

IPsec encryption does not automatically mean the firewall allows the flow. The firewall still evaluates security policy. A missing, shadowed, or overly restrictive policy can block traffic even while IKE and IPsec SAs are established. The **default interzone deny is silent** — no log entry unless logging is explicitly enabled on the deny rule.

### Checks

```
# Policy lookup test
test security-policy-match source 10.10.0.5 destination 192.168.100.5 \
    destination-port 443 protocol 6

# Session table check
show session all filter source <source-ip> destination <destination-ip>

# Monitor
Monitor > Traffic
Monitor > Threat
Monitor > System
```

### Required Policy Directions

| Direction | Source Zone | Destination Zone | Source | Destination |
|---|---|---|---|---|
| Local to remote | Trust | VPN | Local subnet | Remote subnet |
| Remote to local | VPN | Trust | Remote subnet | Local subnet |

Use narrow, test-specific rules during troubleshooting. Once the flow is proven, replace temporary test rules with least-privilege production rules that match required applications and services.

---

## 8. Root Cause 4 — NAT Breaks the Encryption Domain

NAT can change the packet before it reaches the VPN decision. If the proxy ID, selector, or crypto ACL expects the real source address but the firewall translates it first, the packet may no longer match the encryption domain. If the local LAN is subject to an outbound NAT rule (e.g., a catch-all internal → internet masquerade), that rule will also match traffic destined for the VPN peer unless a **no-NAT rule with higher priority** is in place.

### Symptoms

- Tunnel is up, but encapsulation counters do not increase
- Traffic logs show translated IP addresses that are not part of the selector
- Cisco ASA crypto ACL hit count stays at zero while NAT hit count increases
- Only traffic from one source subnet works after a NAT rule change

### Design Decision Table

| VPN Design | Selector Should Contain |
|---|---|
| No NAT over VPN | Real inside source and destination IPs |
| Source NAT over VPN | Translated source IP and real or translated destination according to design |
| Destination NAT before VPN | Real source and translated destination if translation occurs before VPN selection |
| Bidirectional NAT | The exact translated pair as seen by the IPsec decision process |

### NAT Exemption Pattern

```
# NAT rule — must be ABOVE the catch-all masquerade rule
Name: vpn-no-nat
Source zone: trust
Source addr: 10.10.0.0/24
Dest zone: vpn
Dest addr: 192.168.100.0/24
Translation: none (No Source Translation)

# Verify NAT policy
show running nat-policy
```

### Fix

1. Identify whether NAT is intended for this VPN flow
2. If NAT is **not intended**: create or repair NAT exemption rules above the catch-all masquerade
3. If NAT **is intended**: ensure both peers use the translated address space in selectors, crypto ACLs, and routes
4. Confirm NAT order — a correct rule in the wrong order is still wrong
5. Retest with one known source and destination pair

---

## 9. Root Cause 5 — GRE, IPsec, MTU, MSS, and DF-Bit Blackholing

IPsec adds encapsulation overhead: ESP in tunnel mode adds **50–80 bytes** depending on cipher and authentication algorithm. GRE adds a further **24 bytes**. A packet that fits before encapsulation may exceed the path MTU after encapsulation. When the packet has the Don't Fragment (DF) bit set and PMTUD feedback is blocked or not honored, the packet is dropped **silently**.

### GRE over IPsec — Why It Compounds the Problem

A plain IPsec tunnel can leverage Path MTU Discovery (PMTUD) by generating ICMP Type 3 Code 4 (fragmentation needed) messages. GRE tunnels do not automatically propagate PMTUD signals:

- The GRE tunnel interface presents its MTU as 1476 (1500 − 24 GRE) to the routing layer
- When GRE-encapsulated frames are then IPsec-encapsulated, total overhead may exceed 1500 bytes
- If the DF bit is set on the original packet, the packet is **silently dropped** — no ICMP is generated toward the sender

### Classic Symptom Pattern

```
ping -s 100   → succeeds
ping -s 1400  → fails
HTTP works. HTTPS hangs after TLS handshake. SMB/CIFS file copies stall at ~4KB.
```

### Fixes

| Approach | PAN-OS Config | Notes |
|---|---|---|
| Reduce tunnel interface MTU | Network → Interfaces → Tunnel → MTU → set to 1350 or lower | Conservative. Works for both IPsec-only and GRE-over-IPsec |
| TCP MSS clamping | Zone protection profile → TCP settings → MSS adjustment → 1350 | Only clamps TCP SYN/SYN-ACK. Does not help UDP or established sessions. Preferred for most deployments |
| Clear DF bit | IPsec tunnel advanced settings → Copy DF bit: No | Allows fragmentation. May increase latency on high-throughput paths. Last resort |
| GRE tunnel MTU | Set GRE tunnel interface MTU to ~1404 (1476 − IPsec overhead ~72) | Ensures GRE+IPsec fits inside physical MTU |

### MTU Starting Points by Scenario

| Scenario | Suggested Starting Point |
|---|---|
| IPsec only | MTU 1400, MSS 1360 |
| GRE over IPsec | MTU 1360 or lower, MSS 1320 or lower |
| Internet path with PPPoE or extra overlay | Test down to 1300 or 1280 |
| Azure or cloud VPN path | Start around 1350 to 1400 and validate with DF ping |

### DF-Bit Test Commands

```
# Windows
ping <remote-ip> -f -l 1472
ping <remote-ip> -f -l 1400
ping <remote-ip> -f -l 1360
ping <remote-ip> -f -l 1320

# Linux
ping -M do -s 1472 <remote-ip>
ping -M do -s 1400 <remote-ip>
ping -M do -s 1360 <remote-ip>
ping -M do -s 1320 <remote-ip>

# PAN-OS dataplane ping with DF set
ping source 10.10.0.1 host 192.168.100.5 size 1300 df-bit yes
ping source 10.10.0.1 host 192.168.100.5 size 1400 df-bit yes

# Check global counter for DF-bit drop events
show counter global filter delta yes severity drop | match mtu
```

> For IPv4 ICMP testing, payload size plus 28 bytes approximates the full IP packet size. A Windows test of `-l 1372` corresponds to an approximate 1400-byte packet.

---

## 10. Root Cause 6 — PSK Rotation Problems

Pre-shared key rotation is operationally hazardous when both peers don't update simultaneously. A PSK mismatch can be **hidden until renegotiation**. Existing SAs can remain active temporarily (IKEv1 Phase 1 SAs have a lifetime commonly of 8 hours), so a mismatch may not surface until the SA attempts to re-key hours after the change was made on only one peer.

### Symptoms

- Tunnel stayed up after one side changed the PSK, then failed later
- Tunnel fails immediately after clearing IKE or IPsec SAs
- Logs show authentication failure
- One administrator rotated the key, but the peer still has the old value

> **⚠ Change Window Timing:** Always rotate PSKs during a maintenance window. Update both peers before the existing Phase 1 SA expires. IKEv1 will not renegotiate until expiry, so a mismatch may not fail immediately — giving false confidence that the change succeeded.

### Fix Process

1. Schedule a coordinated key rotation window
2. Confirm both administrators are modifying the correct gateway or tunnel object
3. Stage the new PSK on both peers
4. Commit or apply both configurations close together
5. Clear IKE and IPsec SAs
6. Reinitiate Phase 1 and Phase 2
7. Test real application traffic, not only tunnel status

```
# Force Phase 1 renegotiation after PSK update to test immediately
test vpn ike-sa gateway GATEWAY-NAME
show vpn ike-sa gateway GATEWAY-NAME
test vpn ipsec-sa tunnel TUNNEL-NAME
show vpn ipsec-sa tunnel TUNNEL-NAME

# Check for auth-failure events in system log
show log system subtype equal vpn | match authentication
```

---

## 11. Root Cause 7 — IKEv1 vs. IKEv2 Negotiation Mismatch

IKEv1 and IKEv2 are different negotiation protocols. Both peers must support and agree on the same IKE version. PAN-OS supports IKEv1, IKEv2, and IKEv2 preferred modes. When set to **IKEv2 preferred**, PAN will attempt IKEv2 first and fall back to IKEv1 — but some peers do not handle version negotiation gracefully and may reset the SA instead of downgrading.

**Always hard-pin the IKE version to match the peer** rather than relying on auto-negotiation in production environments.

### Required Matching Settings

| Setting | Requirement |
|---|---|
| IKE version | Must match or be mutually supported |
| Authentication method | Must match |
| Peer ID / Local ID | Must match peer expectations |
| Encryption algorithm | Must have compatible proposal |
| Integrity algorithm | Must have compatible proposal |
| DH group | Must have compatible proposal |
| NAT-T | Should be compatible when NAT exists between peers |

### IKE Version Compatibility by Peer

| PAN Setting | Cisco ASA Behavior | Azure VPN (Route-Based) | Fortinet |
|---|---|---|---|
| IKEv2 preferred | ASA 9.7+ handles fallback; older firmware drops the initial IKEv2 INIT | Route-based supports IKEv2 natively — preferred | Works if FortiGate IKEv2 is enabled on the Phase 1 profile |
| IKEv1 only | Safe with any ASA firmware; required for policy-based Azure | Policy-based Azure requires IKEv1 | Safe; some older FortiOS also IKEv1-only by default |

### Fix

- Verify whether the peer supports IKEv1, IKEv2, or both
- Use IKEv2 where possible for modern deployments, unless a peer or cloud design requires otherwise
- Confirm the IKE gateway proposal, peer identification, and authentication method
- Clear stale SAs after changing IKE version

---

## 12. Root Cause 8 — PFS Group Mismatch

Perfect Forward Secrecy (PFS) is a Phase 2 setting that derives a fresh Diffie-Hellman key for each Phase 2 SA, independent of the Phase 1 key. If one peer requires PFS and the other disables it, or if both peers use different PFS groups, **Phase 2 can fail at rekey**. The tunnel may work for the full Phase 2 lifetime (default 1 hour on PAN-OS) and then begin dropping traffic as the SA attempts to re-key.

> **Asymmetric Failure Timing:** A PFS group mismatch creates an intermittent failure that appears unrelated to any configuration change — the first Phase 2 SA may succeed if PFS was disabled on one side during initial setup.

### Phase 2 Parameters to Check

| Phase 2 Parameter | Must Be Checked |
|---|---|
| ESP encryption | Example: AES-256-CBC, AES-256-GCM |
| ESP authentication / integrity | Example: SHA-256, SHA-384, or null with GCM as appropriate |
| PFS enabled or disabled | Both peers must agree |
| PFS group | Must match when PFS is enabled |
| Lifetime | Should be compatible |
| Protocol | Usually ESP |

### Default PFS Groups by Platform

| PAN-OS Default | Cisco ASA Default | Azure Default | Fortinet Default |
|---|---|---|---|
| Group 14 (2048-bit MODP) | Group 2 (older); Group 14 on ASA 9.8+ | Group 2 (policy-based); Group 14 or 24 (route-based) | Group 5 or Group 14 depending on firmware |

The safest approach is to explicitly configure both sides to the same group rather than relying on defaults. **Group 14** is broadly compatible and NIST-approved. Groups 19, 20, and 21 (ECDH) provide stronger security but require firmware support on all peers.

### Fix on PAN-OS

In the IPsec Crypto Profile (**Network → Network Profiles → IPsec Crypto**), set the DH Group field explicitly.

```
# Verify negotiated PFS group from active SA
show vpn ipsec-sa gateway GATEWAY-NAME
# Look for 'dh-group' in the SA detail output

# On Cisco ASA — confirm PFS config
show crypto ipsec sa detail | include PFS
```

---

## 13. Standard Troubleshooting Workflow

1. **Pick one real test flow.** Record source IP, destination IP, protocol, source port, and destination port.
2. **Confirm the packet arrives** at the local firewall.
3. **Confirm routing** sends the packet to the VPN tunnel.
4. **Confirm NAT** preserves or intentionally translates the packet according to design.
5. **Confirm the packet matches** the proxy ID, traffic selector, crypto ACL, or Phase 2 selector.
6. **Confirm security policy** allows the packet.
7. **Check encapsulation and decapsulation counters.**
8. **Confirm the remote peer** routes the reply back into the tunnel.
9. **Test MTU and MSS** if small traffic works but large traffic fails.
10. Only rebuild the tunnel after the above evidence shows a negotiation or configuration problem.

### 4-Stage Packet Capture

```
debug dataplane packet-diag set filter match source 10.10.0.5 destination 192.168.100.5
debug dataplane packet-diag set filter on
debug dataplane packet-diag set log feature forwarding basic
debug dataplane packet-diag set log on

# After replicating the issue, collect output
debug dataplane packet-diag show log
debug dataplane packet-diag clear
```

### Counter Interpretation

| Counter Pattern | Meaning |
|---|---|
| Encaps increasing, decaps not increasing | Local firewall sends encrypted traffic, but peer or return path is failing |
| Decaps increasing, encaps not increasing | Peer sends traffic, but local firewall is not sending replies into tunnel |
| Neither increasing | Traffic is not matching route, policy, NAT, or selector |
| Both increasing | VPN is passing packets — investigate host firewall, application, asymmetric routing, or MTU |

### Flow Worksheet

| Field | Value (fill in during troubleshooting) |
|---|---|
| Source IP | |
| Destination IP | |
| Protocol | |
| Destination port | |
| Source zone | |
| Destination zone | |
| Ingress interface | |
| Egress interface | |
| NAT rule matched | |
| Security rule matched | |
| Route matched | |
| Proxy ID / selector matched | |
| Encap counter before test | |
| Encap counter after test | |
| Decap counter before test | |
| Decap counter after test | |

---

## 14. Platform Command Reference

### Palo Alto Networks PAN-OS

```
show vpn ike-sa gateway <gateway-name>
show vpn ike-sa tunnel <tunnel-name>
show vpn ipsec-sa tunnel <tunnel-name>
show vpn flow
show running tunnel flow info
show routing route destination <remote-ip>
show routing fib lookup virtual-router <vr-name> ip <remote-ip>
show session all filter source <src> destination <dst>
test security-policy-match source <src> destination <dst> protocol <p> destination-port <port>
test routing fib-lookup virtual-router default ip <remote-ip>
less mp-log ikemgr.log
tail follow yes mp-log ikemgr.log
```

### Cisco ASA

```
show crypto ikev1 sa
show crypto ikev2 sa
show crypto ipsec sa
show crypto ipsec sa detail | include PFS
show access-list
show nat
packet-tracer input inside tcp <src-ip> <src-port> <dst-ip> <dst-port>
debug crypto isakmp 255
```

### Fortinet FortiGate

```
get vpn ipsec tunnel summary
diagnose vpn tunnel list
diagnose debug reset
diagnose debug application ike -1
diagnose debug enable
```

### Microsoft Azure VPN Gateway

- Check VPN connection status
- Check local network gateway prefixes
- Check virtual network address space
- Check custom traffic selectors
- Check configured IPsec/IKE policy
- Check effective routes on impacted subnets and network interfaces
- Check NSGs, Azure Firewall, NVA routing, and UDRs
- Check NAT configuration and policy-based traffic selector limitations
- Check BGP configuration if route-based gateway is in use

---

## 15. Resolution Checklist

| Area | Validation Items |
|---|---|
| **Phase 1** | Peer IP, IKE version, PSK or certificate, peer ID, encryption, integrity, DH group, lifetime, NAT-T |
| **Phase 2** | ESP encryption, ESP integrity, PFS enabled or disabled, PFS group, lifetime, protocol, selectors |
| **Routing** | Remote route points to tunnel, return route exists, correct virtual router, no more-specific route conflict |
| **Security policy** | Correct source and destination zones, allowed application and service, logs enabled on deny rule |
| **NAT** | NAT exemption if no NAT intended, correct translated addresses if NAT intended, correct rule order |
| **MTU and MSS** | DF-bit test completed, tunnel MTU adjusted, MSS adjusted, ICMP fragmentation-needed allowed |

### General Best Practices

- Hard-pin IKE version, DH group, and PFS group in crypto profiles rather than relying on negotiation
- Always configure explicit Proxy-IDs when peering with non-PAN devices
- Set tunnel interface MTU to 1350 as a safe baseline for any GRE-over-IPsec topology
- Document PSK rotation procedures with simultaneous peer update steps

---

## 16. Escalation Data to Collect

| Field | Value |
|---|---|
| Tunnel name | |
| IKE gateway name | |
| Peer public IP | |
| Local public IP | |
| IKE version | |
| Phase 1 proposal | |
| Phase 2 proposal | |
| PFS setting | |
| Proxy IDs / traffic selectors | |
| Local subnets | |
| Remote subnets | |
| NAT rules | |
| Security rules | |
| Routes | |

**Collect from CLI:**
```
show vpn ike-sa
show vpn ipsec-sa
show vpn flow
show log system subtype equal vpn
```

Include: relevant system logs, packet captures, DF-bit MTU test results, timestamp of failed test, source/destination IP used in test, protocol and port.

---

## 17. References

| Source | Reference |
|---|---|
| PAN-OS | Proxy ID for IPsec VPN: https://docs.paloaltonetworks.com/network-security/ipsec-vpn |
| PAN-OS | Troubleshooting Site-to-Site VPN Issues Using CLI: https://docs.paloaltonetworks.com/network-security/ipsec-vpn/administration/troubleshooting |
| PAN-OS | Define IPsec Crypto Profiles: https://docs.paloaltonetworks.com/network-security/ipsec-vpn/administration/set-up-site-to-site-vpn/define-cryptographic-profiles |
| Cisco | Most Common IPsec VPN Troubleshooting Solutions: https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation-firewalls/81824-common-ipsec-trouble.html |
| Cisco | Resolve IPv4 Fragmentation, MTU, MSS, and PMTUD Issues with GRE and IPsec: https://www.cisco.com/c/en/us/support/docs/ip/generic-routing-encapsulation-gre/25885-pmtud-ipfrag.html |
| Fortinet | Phase 2 configuration: https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/604285/phase-2-configuration |
| Azure | Traffic selectors in a VPN gateway: https://learn.microsoft.com/en-us/azure/vpn-gateway/custom-traffic-selectors |
| Azure | IPsec/IKE policy for S2S VPN connections: https://learn.microsoft.com/en-us/azure/vpn-gateway/ipsec-ike-policy-howto |
| RFC | RFC 2784 — Generic Routing Encapsulation: https://www.rfc-editor.org/rfc/rfc2784 |

---

## Final Diagnostic Summary

When a site-to-site IPsec tunnel is up but traffic does not pass, the fastest path to resolution is to **follow one real packet**. In most escalations, the failure is one of five conditions: selector mismatch, missing route, NAT exemption error, security policy block, or MTU/MSS blackhole. Proposal mismatches, PSK rotation, IKE version mismatch, and PFS mismatch become most visible during tunnel initiation or rekey.

**Use the 6-step unified workflow:** confirm tunnel state → check proxy-IDs → MTU test → policy lookup → NAT check → route check → packet capture.

*End of Article KB-PAN-VPN-001*
