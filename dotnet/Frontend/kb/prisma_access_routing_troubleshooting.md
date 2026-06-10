# KB-PA-ROUTING-001 — Prisma Access: Routing, Service Connections, Remote Networks, BGP & Advanced Troubleshooting

**Article ID:** KB-PA-ROUTING-001  
**Applies To:** Prisma Access (Cloud-Managed & Panorama-Managed)  
**Audience:** Network Engineering, SOC, Firewall Engineering, Cloud Security, Escalation Teams  
**Scope:** Private access routing, remote networks, service connections, BGP, NAT, failover  
**Revision:** 1.0 — May 2026

---

> **CORE PRINCIPLE:** Authentication proves that a mobile user can *enter* Prisma Access. It does **not** prove that Prisma Access has a route to the private application, that the return path exists, that policy allows the session, or that NAT preserves User-ID / Device-ID context.

---

## Table of Contents

1. [Overview and Scope](#1-overview-and-scope)
2. [Prisma Access Routing Architecture](#2-prisma-access-routing-architecture)
3. [Service Connections](#3-service-connections)
4. [Remote Networks](#4-remote-networks)
5. [BGP in Prisma Access — Deep Dive](#5-bgp-in-prisma-access--deep-dive)
6. [Core Troubleshooting Principle](#6-core-troubleshooting-principle)
7. [Common Symptoms and Likely Causes](#7-common-symptoms-and-likely-causes)
8. [Baseline Validation Checklist](#8-baseline-validation-checklist)
9. [Troubleshooting Scenarios](#9-troubleshooting-scenarios)
10. [Recommended Troubleshooting Workflow](#10-recommended-troubleshooting-workflow)
11. [BGP Design Best Practices](#11-bgp-design-best-practices)
12. [Known High-Value Checks](#12-known-high-value-checks)
13. [Example Decision Tree](#13-example-decision-tree)
14. [Resolution Patterns](#14-resolution-patterns)
15. [Preventive Design Recommendations](#15-preventive-design-recommendations)
16. [Diagnostic Command Reference](#16-diagnostic-command-reference)
17. [Escalation Data to Collect](#17-escalation-data-to-collect)
18. [Best Practices Summary](#18-best-practices-summary)
19. [Quick Reference Checklist](#19-quick-reference-checklist)
20. [Final Diagnostic Rule](#20-final-diagnostic-rule)

---

## 1. Overview and Scope

Prisma Access is Palo Alto Networks' cloud-delivered security platform that inspects and routes traffic for mobile users (GlobalProtect agents), remote networks (IPsec tunnel-connected branch sites), and headquarters environments connected via service connections. Because the forwarding plane spans multiple logical constructs — mobile users, remote networks, service connections, BGP, static routes, security policy, NAT, and cloud-managed service state — troubleshooting routing failures is significantly more complex than on a traditional on-premises firewall.

| Product / Technology | Included Scope |
|---|---|
| Prisma Access | Mobile users, remote networks, service connections, private application access, cloud dataplane routing |
| GlobalProtect | Authenticated mobile users and assigned mobile user IP pools |
| Remote Networks | Branch, SD-WAN, site, and IPsec connected locations |
| Service Connections / Corporate Access Nodes | Private application reachability, mobile-to-data-center access, remote-network-to-private-app access |
| Routing | Static routes, BGP, route filtering, route advertisements, prefix overlap, path preference |
| Security Controls | Security policy, NAT policy, User-ID, Device-ID, logs, and session troubleshooting |

---

## 2. Prisma Access Routing Architecture

### 2.1 Logical Plane Overview

| Construct | Description |
|---|---|
| Infrastructure GW | The Prisma Access-managed cloud gateway that terminates tunnels, applies policy, and forwards traffic. Runs a PAN-OS forwarding plane. |
| Mobile Users | Endpoints running GlobalProtect that connect via SSL/IPsec to the nearest Infrastructure GW. Assigned an IP from the Mobile User IP Pool. |
| Remote Networks | Branch sites connected to Prisma Access via IPsec tunnels (typically from SD-WAN or traditional routers). Advertise subnets via BGP or static routes. |
| Service Connections | IPsec or SD-WAN tunnels connecting Prisma Access to a corporate HQ, data center, or cloud environment hosting private applications. |
| BGP on Prisma Access | Supports eBGP peering on service connections and remote network connections. Used to dynamically exchange route information with on-premises or cloud infrastructure. |
| Routing Domain | Prisma Access maintains separate routing domains per tenant. Routes from remote networks, service connections, and mobile user pools are distributed across infrastructure gateways. |
| Panorama / Cloud Management | The management plane; pushes configuration changes. Route state, tunnel state, and BGP adjacency live in the data plane of the Infrastructure GWs. |

### 2.2 Traffic Flow Matrix

| Source | Destination | Path Description |
|---|---|---|
| Mobile User | Internet | GlobalProtect → Infra GW → Internet egress (split-tunnel or full-tunnel depending on policy) |
| Mobile User | Private App (HQ) | GlobalProtect → Infra GW → **Service Connection** tunnel → HQ/DC network |
| Mobile User | Remote Network resource | GlobalProtect → Infra GW → Internal route propagation → Remote Network Infra GW → IPsec tunnel → Branch |
| Remote Network | Internet | Branch router → IPsec tunnel → Infra GW → Internet egress |
| Remote Network | Private App (HQ) | Branch router → IPsec tunnel → Infra GW → **Service Connection** → HQ |
| Remote Network | Mobile User | Requires route propagation via service connection or internal routing; Mobile User IP Pool must be routable |
| HQ / DC | Mobile User | HQ router → Service Connection tunnel → Infra GW → Mobile User (return traffic via pool route) |

> **ARCHITECTURE NOTE:** Traffic between mobile users and remote networks always traverses the Prisma Access infrastructure; there is no direct client-to-branch path.

### 2.3 Route Propagation Model

- Remote network subnets are advertised into the Prisma Access routing domain and become reachable from mobile users and service connections.
- Mobile user IP pools are distributed as host routes or pool-level prefixes and are reachable from HQ via the service connection.
- Service connection routes learned via BGP or static configuration are distributed and available to both mobile users and remote networks.
- Route propagation is **eventual-consistent**; changes made in Panorama or Cloud Manager may take several minutes to propagate across all infrastructure gateways.

---

## 3. Service Connections

### 3.1 What Service Connections Do

A service connection (SC) is an IPsec tunnel that connects Prisma Access to your private corporate infrastructure. Service connections serve two distinct functions:

1. **Private App Reachability:** Mobile users and remote networks that need to access private applications hosted on-premises use the service connection as the egress path.
2. **Mobile-to-Remote Communication:** Without a service connection configured, mobile users and remote network users **cannot communicate with each other**. The service connection acts as the backplane that allows this east-west traffic.

> **KEY DIAGNOSTIC:** If mobile users cannot reach remote network resources, or remote network users cannot reach mobile users, the first question is: **Is a service connection configured and operational?**

### 3.2 Service Connection Configuration Requirements

| Parameter | Required Value / Constraint | Notes |
|---|---|---|
| Tunnel Interface | IKEv1 or IKEv2 IPsec | Match peer IKE version; IKEv2 preferred |
| Authentication | Pre-shared key or certificate | PSK most common |
| BGP Peer IP | IP on the tunnel /30 or /31 | Prisma Access and on-prem peer must be in same /30 |
| BGP AS Number | Unique private AS (64512–65534) | Do not reuse AS across multiple service connections |
| Advertised Subnets | All subnets Prisma Access should reach via SC | Must include HQ LAN and app subnets |
| Mobile User IP Pool | Must be routed back toward Prisma Access | HQ firewall/router needs a static or BGP route for this pool |
| Primary / Secondary SC | One primary, optional secondary for HA | Failover behavior is configurable |
| Onboarding Region | Must match SC region | Affects tunnel endpoint IP selection |

### 3.3 BGP on Service Connections

BGP is the recommended dynamic routing protocol for service connections. Prisma Access acts as the eBGP neighbor using the tunnel interface IP.

**Prisma Access BGP Peer Configuration (Cloud Manager):**
```
Service Connection → BGP → Enable BGP
  Peer AS: <your-campus-AS>
  Peer IP: <HQ-tunnel-IP>        (e.g., 10.254.0.2)
  Local IP: <PA-tunnel-IP>       (e.g., 10.254.0.1)
  Keepalive: 10 seconds
  Hold Time: 30 seconds
  Authentication: MD5 (optional but recommended)
```

**HQ Router BGP Configuration (IOS-XE Example):**
```
router bgp 65001
  bgp router-id 10.1.1.1
  neighbor 10.254.0.1 remote-as 65000
  neighbor 10.254.0.1 description Prisma-Access-SC
  neighbor 10.254.0.1 password <md5-key>
  !
  address-family ipv4
    neighbor 10.254.0.1 activate
    network 10.1.0.0 mask 255.255.0.0
    network 10.2.0.0 mask 255.255.0.0
    neighbor 10.254.0.1 soft-reconfiguration inbound
  exit-address-family
```

> **WARNING:** Prisma Access BGP AS for service connections is typically **65000** (default) but can vary by deployment. Verify the correct AS in the service connection settings before configuring the HQ peer.

### 3.4 Service Connection Failover

| Behavior | Detail |
|---|---|
| Detection Method | Prisma Access uses BFD and IPsec DPD (Dead Peer Detection) to detect tunnel failures. BGP hold-time expiry is also a trigger. |
| Failover Trigger | Primary SC tunnel down, BFD failure, or BGP session lost. Failover occurs within configured BFD/DPD interval (typically 3–5 seconds). |
| Preemption | By default, Prisma Access does **NOT** preempt back to the primary after recovery. Enable **Primary Preferred** in SC settings if preemption is desired. |
| Asymmetric Routing Risk | If the HQ has multiple uplinks to different service connections, asymmetric routing can occur. Ensure BGP route preferences are consistent on both sides. |
| BGP Path After Failover | After failover, routes previously learned via the primary SC must be re-advertised by the secondary. If routes were not pre-established on the secondary, there will be a reconvergence delay. |
| Testing Failover | Shut the primary SC tunnel interface on the **HQ device**. Verify BGP reconverges and traffic flows via secondary. Do NOT test by disabling Prisma Access side only — the GW may retain stale routes. |

**DPD Configuration:**
```
IKE Gateway → Advanced → Dead Peer Detection
  Action: restart
  Interval: 10 seconds
  Retry: 5
```

---

## 4. Remote Networks

### 4.1 Remote Network Architecture

A remote network represents a branch office or remote site connected to Prisma Access via an IPsec tunnel. The on-premises router (CPE) acts as the **tunnel initiator**. Prisma Access is always the **responder**. Once the tunnel is established, routing must be configured to make Prisma Access aware of the branch subnets.

### 4.2 Routing Options for Remote Networks

| Routing Method | Details |
|---|---|
| Static Routes | Subnets at the remote site are manually defined in the remote network configuration. Simple but does not adapt to changes at the branch. |
| BGP (eBGP) | The CPE router establishes a BGP session over the IPsec tunnel. The CPE advertises its LAN subnets; Prisma Access redistributes these into its internal routing domain. Recommended for dynamic routing needs or SD-WAN fabrics. |
| BGP with Route Filtering | Use BGP prefix lists and route maps on the CPE side to control exactly which routes are sent to Prisma Access. |

> **IMPORTANT DESIGN RULE:** When static routes and BGP are both configured for remote networks, **static routes take precedence over BGP**. An old static route can silently override a correct BGP route.

### 4.3 Static Route Configuration

```
Panorama → Prisma Access → Remote Networks → <Site> → Routing
  Routing Type: Static
  Subnets:
    10.50.1.0/24  (Branch LAN - Workstations)
    10.50.2.0/24  (Branch LAN - Servers)
    10.50.3.0/24  (Branch LAN - VoIP)
```

**CPE side — route toward Prisma Access:**
```
! Route toward Prisma Access for Mobile User Pool
ip route 10.0.0.0 255.255.0.0 Tunnel0

! Route toward Prisma Access for HQ subnet
ip route 10.1.0.0 255.255.0.0 Tunnel0
```

### 4.4 BGP Configuration for Remote Networks

**Prisma Access Remote Network BGP Settings (Cloud Manager):**
```
Remote Network → <Site> → Routing → BGP
  Enable BGP: Yes
  Peer AS: 65100  (Branch CPE AS)
  Do Not Export Routes: [Leave unchecked unless intentional]
  Summarize Mobile User Routes: Yes  (optional, reduces prefix count)
```

**Branch CPE BGP Config (Cisco IOS-XE):**
```
router bgp 65100
  bgp router-id 10.50.0.1
  neighbor 169.254.0.1 remote-as 65000
  neighbor 169.254.0.1 description Prisma-Access-RN
  !
  address-family ipv4
    neighbor 169.254.0.1 activate
    network 10.50.1.0 mask 255.255.255.0
    network 10.50.2.0 mask 255.255.255.0
    neighbor 169.254.0.1 soft-reconfiguration inbound
    neighbor 169.254.0.1 route-map BRANCH-OUT out
  exit-address-family

ip prefix-list BRANCH-PREFIXES seq 5 permit 10.50.0.0/16 le 24
route-map BRANCH-OUT permit 10
  match ip address prefix-list BRANCH-PREFIXES
```

> **CRITICAL WARNING:** Avoid advertising a **default route (0.0.0.0/0)** from the branch CPE to Prisma Access. This will cause Prisma Access to route all internet traffic through the branch tunnel, creating a hairpin and likely overloading the CPE uplink.

### 4.5 Tunnel Monitoring and Route Validation

```bash
# Check BGP peer status
> show routing protocol bgp peer

# Check BGP RIB for routes received from branch
> show routing protocol bgp loc-rib

# Check active routing table
> show routing route

# Check tunnel status
> show vpn tunnel
> show vpn ike-sa
> show vpn ipsec-sa
```

---

## 5. BGP in Prisma Access — Deep Dive

### 5.1 BGP Architecture Summary

- Each service connection and each remote network has its own independent BGP session.
- Prisma Access uses a fixed AS (commonly **65000** for cloud-managed deployments) unless overridden.
- BGP routes learned from remote networks are propagated to mobile users and service connections by the Prisma Access control plane.
- BGP routes learned from service connections are propagated to both mobile users and remote networks.
- Prisma Access advertises GlobalProtect mobile user IP pools in **/24 blocks** in BGP route advertisements. CPE prefix-lists that only permit larger summaries can accidentally **reject these /24 advertisements**.

### 5.2 Common BGP Issues and Root Causes

| Symptom | Root Cause / Investigation |
|---|---|
| BGP session not established | Tunnel not up (check IKE/IPsec), AS mismatch, incorrect peer IP, firewall blocking TCP 179 on tunnel interface |
| BGP established but no routes received | CPE not advertising routes, route-map filtering all prefixes, soft-reconfiguration not enabled, CPE redistributing but not originating networks |
| Routes received but not installed | Route preference conflict (static route wins), route already in table via another path, administrative distance of BGP too high |
| Routes too broad (e.g., 0.0.0.0/0) | CPE redistributing default route; apply outbound route-map to block 0.0.0.0/0 before advertising to Prisma Access |
| Routes too narrow (only /32 hosts) | CPE redistributing connected interfaces instead of summarized networks; switch to `network` statements with correct masks |
| BGP flapping | Unstable tunnel (DPD failures, IKE re-keying issues), hold-time too short, high latency causing keepalive timeouts — increase hold-time to 90s for higher-latency links |
| Asymmetric routing post-failover | Primary and secondary SCs have different route preferences; standardize BGP local-preference and MED values across both paths |
| AS_PATH loop prevention | If HQ and branch use the same AS, Prisma Access will drop routes due to AS_PATH loop detection — use unique AS per site or configure AS override |

### 5.3 BGP Route Advertisement Best Practices

- **Be specific, not broad.** Advertise actual subnet prefixes (/24, /23) that exist at each site. Avoid summarizing to /8 or /16 unless you own and use the entire block.
- **Filter on both directions.** Apply inbound and outbound prefix lists on the CPE. Inbound filtering prevents Prisma Access from sending unwanted routes to the branch.
- **Use community strings for visibility.** Tag routes with BGP communities to distinguish mobile-user-pool routes, HQ routes, and branch routes.
- **Set appropriate timers.** For IPsec-based BGP, default keepalive (60s) and hold-time (180s) may result in slow failure detection. Consider 10/30 for LAN-quality tunnels, 20/60 for WAN-quality.
- **Summarize Mobile User Pools.** Enable the **Summarize Mobile User Routes** option in Prisma Access to advertise the pool as a single summary instead of per-host /32 routes.

---

## 6. Core Troubleshooting Principle

Every Prisma Access private access flow requires **all** of the following conditions to be true. Treat this table as the first diagnostic pass before focusing on a specific symptom.

| Step | Question | Failure Result |
|---|---|---|
| 1 | Did the user or site connect successfully? | No dataplane path exists. |
| 2 | Does Prisma Access have a route to the destination? | Traffic is dropped or forwarded to the wrong place. |
| 3 | Does the destination side have a return route? | One-way traffic or timeout. |
| 4 | Did BGP advertise and install the correct prefixes? | Routes are missing, filtered, or inactive. |
| 5 | Did static routing override the intended BGP route? | Traffic follows a stale or unintended next hop. |
| 6 | Does security policy allow the actual flow? | The session is denied despite correct routing. |
| 7 | Does NAT preserve the required identity attributes? | User-ID or Device-ID policy fails. |
| 8 | Is Prisma Access selecting the intended path? | Unexpected hairpinning, failover, or latency. |

> Authentication is only an **admission event**. It is not proof of private application reachability, route symmetry, policy match, or identity preservation.

---

## 7. Common Symptoms and Likely Causes

| Symptom | Most Likely Causes |
|---|---|
| Mobile user authenticates but cannot reach private app | Missing service connection, missing route to app subnet, missing return route to mobile pool, security policy deny, DNS issue, source NAT issue |
| Remote network tunnel is up but routes are missing | BGP not established, route filters, missing static route, tunnel monitor state, static/BGP conflict |
| BGP established but traffic fails | Wrong prefixes advertised, return path missing, asymmetric path, policy or NAT issue |
| BGP advertisements too broad | Default route or broad summary advertised unintentionally, no outbound filtering, over-permissive redistribution |
| BGP advertisements too narrow | Prefix-list too restrictive, /24 mobile user routes filtered, missing branch or app subnet advertisements |
| Service connection failover slow or inconsistent | BGP hold timer, tunnel monitoring disabled, static route withdrawal behavior, CPE path selection |
| User-ID or Device-ID disappears behind service connection | Source NAT applied to service-connection traffic without identity preservation design |
| Traffic hairpins through Prisma Access unexpectedly | Default route, more-specific route, service connection routing preference, overlapping prefixes |

---

## 8. Baseline Validation Checklist

### 8.1 Identify the Exact Flow

Convert the complaint into a single five-tuple and the intended forwarding path:
- Source user or source site
- Source IP before Prisma Access
- Source IP after Prisma Access, if NAT is used
- Destination FQDN and resolved destination IP
- Destination subnet and expected service connection or remote network
- Prisma Access location or node involved
- Expected path and actual path from logs or route tables

### 8.2 Confirm Tunnel and Deployment State

- [ ] Config status is **In sync**
- [ ] Tunnel status is **Up** for the relevant service connection or remote network
- [ ] BGP status is **Established** if BGP is used
- [ ] No deployment, license, bandwidth, or cloud service state error is present
- [ ] Traffic logs show the session attempt with the expected source, destination, application, rule, and action

### 8.3 Check Prisma Access Routing Information

- **For the destination:** check exact prefix, more-specific prefix, less-specific summary, and default route behavior
- **For the return path:** check whether Prisma Access advertises the source pool or subnet to the CPE
- **For BGP:** verify peer state, RIB-In, Local RIB, RIB-Out, and route counters
- **For static routing:** verify whether static routes are intentionally overriding BGP

---

## 9. Troubleshooting Scenarios

### 9.1 Mobile Users Cannot Reach Private Apps

> **MOST COMMON CAUSE:** A missing route — the HQ is not advertising the application subnet to Prisma Access via BGP or static route. Verify `show ip bgp neighbors 10.254.0.1 advertised-routes` on the HQ router.

#### Root Cause A: No Service Connection Exists

A mobile user tunnel does **not** automatically create private application connectivity. If private apps live behind the customer WAN or data center, a service connection must exist.

**Validate:**
- At least one service connection exists and is deployed and in sync
- Tunnel status is **Up**
- The service connection has a route to the private application subnet

**Fix:**
- Create or repair the service connection
- Advertise required private app subnets with BGP or configure static routes
- Validate return routes to the Prisma Access mobile user pools

#### Root Cause B: No Route to the App Subnet

**Validate:**
- Search the Prisma Access route table for the exact destination prefix
- Check whether a less-specific route or default route is being used instead
- Check whether an old **static route overrides the intended BGP route**
- Check whether the route is learned through the expected service connection

**Fix:**
- Advertise the application subnet from the CPE using BGP, or configure an explicit static route
- Avoid broad summaries unless the return path and security policy are validated
- Remove stale static routes that override the intended BGP path

#### Root Cause C: Return Route to Mobile User Pool Missing

A TCP session requires a valid return path. If the data center cannot route back to the Prisma Access mobile user pool, the user sees a **timeout** even when the forward path is valid.

**Validate on the Data Center CPE:**
- Check BGP RIB-In from Prisma Access
- Confirm that mobile user /24 routes are received and import policy accepts those routes
- Confirm that the forwarding table installs those routes with Prisma Access as the next hop

**Fix:**
- Update prefix-lists, route-maps, import policies, or maximum-prefix settings to accept expected Prisma Access mobile user /24 advertisements
- Confirm that the return route is **installed in the forwarding table**, not merely received in BGP

#### Root Cause D: Security Policy Blocks the Flow

Routing can be correct while the session is still denied. Check source zone, destination zone, source user, source device, App-ID, service, rule name, action, NAT result, and session end reason.

**Fix:**
- Correct the Prisma Access security rule to allow the intended application flow
- Correct downstream firewall rules if the data center firewall also inspects the traffic
- Account for App-ID dependencies such as `ssl` or `web-browsing` before the final application is identified

#### Root Cause E: NAT Breaks Identity-Based Enforcement

If source NAT is applied before the downstream NGFW enforces User-ID or Device-ID policy, the downstream firewall may only see the NATed address.

**Validate:**
- Check whether the downstream NGFW sees the original mobile user IP or a NATed address
- Run user-to-IP mapping checks for the observed source IP
- Compare the matched downstream security rule against the intended identity-based rule

**Fix — create a no-NAT rule for service-connection-bound traffic:**
```
NAT Rule: No-NAT-to-HQ
  Source Zone:      mobile-users
  Destination Zone: corporate
  Destination:      10.1.0.0/16
  Translation Type: None  (no NAT)
```

```bash
# After disabling SNAT, verify User-ID mapping on the HQ NGFW:
> show user ip-user-mapping all
```

> **IMPORTANT:** User-ID and Device-ID context is preserved only if the **original mobile user IP** is visible to the HQ firewall. Source NAT destroys this context. Always configure a no-NAT rule for service connection-bound traffic when User-ID enforcement is required.

**Diagnostic CLI:**
```bash
> show routing route type bgp
> show routing route destination 10.1.50.0/24
```

---

### 9.2 Remote Network Tunnel Up, Routes Missing

An IPsec tunnel being **Up** proves that tunnel negotiation succeeded. It does **not** prove that BGP is established, that prefixes are being advertised, that filters accept them, or that the forwarding table installed them.

**Validate BGP State:**
- Is BGP **Established**?
- Are incoming route counts nonzero?
- Are outgoing route counts nonzero?
- Does the Local RIB contain the expected remote subnet?
- Are import/export filters blocking the prefix?

**Validate Static Route Precedence:**
- Search the Prisma Access route table for the destination prefix
- Identify whether the active route source is **static** or **BGP**
- Remove obsolete static routes after BGP is confirmed working

**Validate Overlap:**
- Remote network subnets should not overlap with each other, Prisma Access mobile user IP pools, or the Prisma Access infrastructure subnet

**CPE Diagnostic Commands:**
```bash
show ip bgp summary
show ip bgp neighbors 169.254.0.1 advertised-routes

# After correcting configuration, trigger a BGP soft reset:
clear ip bgp 169.254.0.1 soft
```

---

### 9.3 BGP Advertisements Too Broad or Too Narrow

#### Too Broad — Default Route Advertised

**Resolution — block default route from outbound BGP:**
```
ip prefix-list BLOCK-DEFAULT seq 5 deny 0.0.0.0/0
ip prefix-list BLOCK-DEFAULT seq 10 permit 0.0.0.0/0 le 32

route-map BRANCH-OUT permit 10
  match ip address prefix-list BLOCK-DEFAULT
```

#### Too Narrow — /32 Host Routes Only

CPE redistributing connected interfaces without proper `network` statements generates /32 host routes.

**Resolution:**
```
router bgp 65100
  address-family ipv4
    no redistribute connected
    network 10.50.1.0 mask 255.255.255.0
    network 10.50.2.0 mask 255.255.255.0
```

**Additional causes of too-narrow advertisements:**
- Prefix-list only permits large summaries and rejects Prisma Access /24 mobile pool advertisements
- BGP max-prefix limit reached
- Route-map denies longer prefixes

---

### 9.4 Service Connection Failover Not Working

#### Cause A: Tunnel Monitoring Not Enabled

- Enable tunnel monitoring where appropriate
- Use a monitored IP that proves the **intended private path** is alive
- Avoid monitoring an IP that is reachable through multiple alternate paths

#### Cause B: Static Route Withdrawal Behavior Misunderstood

- Confirm whether the deployment is single tunnel or dual tunnel
- Confirm whether tunnel monitoring is enabled
- Confirm whether static route withdrawal is enabled
- Validate that the CPE also changes its path selection after failover

#### Cause C: CPE Still Prefers the Failed Path

- Check CPE BGP neighbor state
- Check local RIB and forwarding table, not only BGP received routes
- Review route-map local preference, AS-path prepending, MED, and administrative distance
- Check SD-WAN policy or policy-based routing that may override the routing table

#### Cause D: Asymmetric Routing Mismatch

- Use symmetric routing when stateful inspection, NAT, or identity preservation requires it
- Check whether load-sharing behavior can move return traffic to a different service connection than expected

> If failback is not occurring, verify **Primary Preferred** is enabled in the service connection HA settings.

---

### 9.5 Source NAT Breaks User-ID or Device-ID

Identity-based policy depends on a stable mapping among user, device, source IP, and session. If source NAT changes the source IP before the downstream NGFW enforces policy, the downstream firewall may only see the NAT address.

**Symptoms:**
- Prisma Access logs show user identity, but data center firewall logs show only an IP or NAT pool
- User-based or Device-ID security rules do not match downstream
- Traffic hits a generic fallback rule
- Application access works with IP-based allow rules but fails with user-based rules

**Diagnostic Steps:**
1. Check NAT policy in Prisma Access: `Policies → NAT`, identify rules that match mobile user source addresses with source translation
2. If SNAT is applied, determine if it is intentional — for traffic toward private apps via service connections, SNAT is typically **NOT** needed
3. Disable SNAT for internal-destined traffic by creating a no-NAT rule (see Section 9.1, Root Cause E)
4. After disabling SNAT, verify User-ID mapping on the HQ NGFW: `> show user ip-user-mapping all`

---

### 9.6 Traffic Hairpins Through Prisma Access

Hairpinning occurs when traffic enters Prisma Access and then exits or returns through a path that was not intended.

| Root Cause | Resolution |
|---|---|
| Branch advertising a default route | Filter 0.0.0.0/0 from BGP advertisement on CPE; apply outbound prefix-list |
| Prisma Access re-advertising branch subnets back to other branches | Enable **Do Not Export Routes** on the receiving remote network |
| No split tunneling configured for inter-branch traffic | Configure split-tunnel include/exclude routes on GlobalProtect |
| Static default route on CPE points to Prisma Access tunnel | Adjust CPE routing so internet-bound traffic uses the CPE's local internet uplink |
| SD-WAN policy sending all traffic to Prisma Access | Review SD-WAN application policy; restrict Prisma Access as next-hop to specific application categories |
| Overlapping RFC1918 space | Check for overlapping private IP space and resolve before onboarding remote networks or service connections |

---

## 10. Recommended Troubleshooting Workflow

| Phase | Actions |
|---|---|
| **Phase 1: Prove the Control Plane** | Config status In sync; service connection or remote network deployed; tunnel Up; BGP Established; no deployment/sync/bandwidth error |
| **Phase 2: Prove the Route** | Confirm Prisma Access route for destination; identify static vs. BGP; check more-specific routes; check return path on CPE |
| **Phase 3: Prove the Policy** | Check source/destination zones, source user/device, application, service, rule name, action, NAT result, session end reason |
| **Phase 4: Prove the Return Path** | Check server default gateway; DC firewall route table; CPE forwarding table; BGP return route advertisement; NAT symmetry |
| **Phase 5: Prove the Actual Packet Path** | Use Prisma Access traffic logs; DC firewall logs; CPE logs; compare RIB-In / Local RIB / RIB-Out; use traceroute or packet capture |

**Step-by-step:**

| Step | Action |
|---|---|
| 1. Confirm Tunnel State | Verify IPsec tunnel (IKE Phase 1 and Phase 2) is **UP** on both sides before investigating routing. |
| 2. Confirm BGP Adjacency | If using BGP, verify session is **Established**. Check for Idle, Active, or Connect states indicating connection-level issues. |
| 3. Check Route Table | Verify that expected prefixes are present in the Prisma Access routing table. Absence explains all downstream failures. |
| 4. Check Security Policy | Confirm a security policy allows traffic from the source zone/IP to the destination zone/IP. |
| 5. Check NAT Policy | If Source NAT is configured, verify it is not breaking return traffic or User-ID/Device-ID context. |
| 6. Use Packet Capture | Use Prisma Access packet capture (CLI or GUI) to follow the packet through ingress, policy lookup, and egress. |
| 7. Check Logs | Traffic logs show policy hit, NAT applied, and egress interface. System logs show tunnel state changes and BGP events. |

---

## 11. BGP Design Best Practices

### 11.1 Advertise Only What Prisma Access Needs

| Recommended to Advertise | Avoid Unless Intentional |
|---|---|
| Specific private application subnets | 0.0.0.0/0 default route |
| Specific remote network subnets | Entire 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16 without design validation |
| Required DNS, identity, authentication, and management service subnets | Overlapping branch summaries |
| Mobile user /24 pools accepted at the data center | Redistribution of all connected or static routes |

### 11.2 Treat Static Routes as High-Risk Overrides

Static routes are useful but easy to forget. In Prisma Access remote network routing, static routes can take precedence over BGP. Use them intentionally, document them, and remove temporary static routes after BGP is deployed.

### 11.3 Account for Mobile User /24 Advertisements

If a mobile user pool is configured as a larger block, do not assume the data center receives that same summary. Confirm the actual route advertisements and ensure CPE import policy **permits the /24s** Prisma Access advertises.

### 11.4 Use BGP Filtering Intentionally

- Prevent route leaks
- Control default route advertisement
- Limit branch-to-branch reachability
- Prevent private app prefixes from being advertised to the wrong location
- Influence active/backup data center pathing

---

## 12. Known High-Value Checks

### 12.1 Mobile Users Cannot Reach Private Apps

1. Mobile user connected and received expected IP pool
2. Service connection exists and tunnel is **Up**
3. Prisma Access route to app subnet exists
4. Data center route back to mobile user /24 exists
5. Prisma Access policy allows traffic
6. Data center firewall policy allows traffic
7. NAT does not break identity
8. DNS resolves to the intended private IP

### 12.2 Remote Network Tunnel Up but Routes Missing

1. BGP peer state (Established?)
2. Peer AS and peer IP correct
3. BGP authentication secret matches
4. CPE route advertisement (not /32 hosts, not 0.0.0.0/0)
5. Prisma Access Local RIB contains branch prefixes
6. Import/export filters not blocking routes
7. Static route precedence not overriding BGP
8. Tunnel monitoring state

### 12.3 Failover Does Not Work

1. Primary and secondary tunnel state
2. Tunnel monitoring enabled with correct probe IP
3. BGP hold timer appropriate for link quality
4. Static route withdrawal behavior configured correctly
5. CPE routing preference after failover
6. BGP local preference / MED / AS-path prepending consistent
7. Asymmetric routing design validated
8. Long-lived sessions may remain pinned to old paths — expected behavior

### 12.4 Hairpinning Occurs

1. Default route advertisements from branch CPE
2. More-specific routes in Prisma Access routing table
3. Traffic steering policy and service connection routing preference
4. `Do Not Export Routes` not enabled on remote networks that should be isolated
5. Overlapping private IP space
6. Static routes overriding intended BGP path

---

## 13. Example Decision Tree

**Case: A mobile user can authenticate but cannot reach 10.20.30.50.**

**Step 1: Confirm Authentication**  
User is connected and has received IP 10.100.12.45. This proves authentication and tunnel establishment only. It does **not** prove route or policy success.

**Step 2: Check Prisma Access Route to Destination**  
Look for `10.20.30.50/32`, `10.20.30.0/24`, or a larger matching prefix in Prisma Access Routing Information.

- If **no route exists** → advertise or statically define the subnet
- If **route exists through wrong service connection** → check BGP preference and static routes
- If **default route selected** → check whether a specific private app route is missing

**Step 3: Check Return Route**  
On the data center CPE, check whether `10.100.12.0/24` or the relevant mobile user /24 is learned from Prisma Access.

- If **missing** → check RIB-Out from Prisma Access
- If **received but not installed** → check CPE route policy
- If **installed to wrong next hop** → check local preference, static route, or SD-WAN policy

**Step 4: Check Policy**  
- If denied in Prisma Access → fix Prisma Access policy
- If allowed in Prisma Access but denied at DC → fix downstream policy
- If user identity missing at DC → investigate NAT and identity preservation

**Step 5: Check NAT**  
If the data center sees a NATed source instead of the mobile user pool, downstream User-ID or Device-ID rules may fail. Correct the NAT design or enforce identity policy before NAT changes the source IP.

---

## 14. Resolution Patterns

| Pattern | Resolution |
|---|---|
| Missing private app route | Advertise the app subnet from the CPE using BGP, or add a static route in Prisma Access. Verify forward and return routes. |
| Static route overrides BGP | Remove stale static route, or document and redesign the intentional override. Confirm BGP route becomes active. |
| BGP filters drop mobile user /24s | Update prefix-list or route-map to accept expected /24 mobile user advertisements and confirm forwarding table installation. |
| Service connection failover is slow | Enable tunnel monitoring, validate monitored IP, confirm static route withdrawal behavior, and validate CPE path selection. |
| User-ID lost after NAT | Avoid source NAT where possible; preserve User-ID / Device-ID with supported design; or move identity enforcement into Prisma Access. |
| Unexpected hairpin | Remove unintended default route, reduce broad summaries, correct traffic steering, and validate service connection routing preference. |

---

## 15. Preventive Design Recommendations

### 15.1 Build a Route Ownership Table

Before deploying Prisma Access, maintain a route ownership table:

| Prefix | Owner | Advertised From | Advertised To | Method | Notes |
|---|---|---|---|---|---|
| 10.20.30.0/24 | Data Center 1 | DC CPE | Prisma Access service connection | BGP | Private apps |
| 10.100.12.0/24 | Prisma Access | Prisma Access | DC CPE | BGP | Mobile users |
| 10.50.0.0/16 | Branch WAN | Branch CPE | Prisma Access remote network | BGP | Remote network |
| 0.0.0.0/0 | Internet egress | Prisma Access or CPE | Branch or mobile users | BGP/static | Only if intentional |

### 15.2 Do Not Mix Static and BGP Casually

If both are required, document which one should win and why. Treat every static route as a potential override of dynamic routing behavior.

### 15.3 Avoid Overlapping Address Space

Overlapping prefixes create ambiguous forwarding. Resolve overlap before onboarding remote networks, service connections, or mobile user pools.

### 15.4 Validate RIB-In, Local RIB, RIB-Out, and FIB

BGP **Established** is not enough. Validate received routes, accepted routes, selected routes, advertised routes, and installed forwarding entries.

### 15.5 Treat NAT as an Identity Boundary

If downstream identity enforcement is required, NAT must be part of the design review. NAT can change the source IP and break the mapping used by User-ID or Device-ID policy.

---

## 16. Diagnostic Command Reference

### 16.1 Prisma Access CLI Commands

| Command | Purpose |
|---|---|
| `show routing route` | Full routing table including all installed routes |
| `show routing route type bgp` | BGP-learned routes only |
| `show routing route destination <prefix>` | Lookup specific prefix in routing table |
| `show routing protocol bgp peer` | BGP peer summary with session state and prefix counts |
| `show routing protocol bgp loc-rib` | Local BGP RIB (routes Prisma Access has selected) |
| `show routing protocol bgp rib-out` | Routes Prisma Access is advertising to BGP peers |
| `show vpn tunnel` | IPsec tunnel status (all tunnels) |
| `show vpn ike-sa` | IKE Phase 1 security association details |
| `show vpn ipsec-sa` | IKE Phase 2 / IPsec SA details and traffic counters |
| `show vpn flow` | IPsec traffic flow counters |
| `show user ip-user-mapping all` | User-ID table (verify mobile user mappings) |
| `show counter global filter delta yes` | Global packet counters; delta mode shows recent increments |

### 16.2 Packet Capture for Path Tracing

```bash
# Stage 1: Capture on ingress (mobile user tunnel interface)
> debug dataplane packet-diag set filter match source <mobile-user-IP>
> debug dataplane packet-diag set filter match destination <app-IP>
> debug dataplane packet-diag set log feature security-policy yes
> debug dataplane packet-diag set log feature route yes
> debug dataplane packet-diag set log feature nat yes
> debug dataplane packet-diag clear filter
> debug dataplane packet-diag set filter on

# Reproduce the issue, then:
> debug dataplane packet-diag show
```

### 16.3 HQ / CPE Validation Commands (IOS-XE)

| Command | Purpose |
|---|---|
| `show ip bgp summary` | BGP peer state, prefix counts, uptime |
| `show ip bgp neighbors <PA-IP> advertised-routes` | Prefixes being sent to Prisma Access |
| `show ip bgp neighbors <PA-IP> routes` | Prefixes received from Prisma Access |
| `show ip route bgp` | BGP routes installed in routing table |
| `show crypto ikev2 sa` | IKEv2 Phase 1 SA state |
| `show crypto ipsec sa` | IPsec Phase 2 SAs and packet counters |
| `ping <dest> source <tunnel-src> repeat 100` | Verify tunnel path connectivity |
| `traceroute <dest> source <tunnel-src>` | Trace the forwarding path through the tunnel |

---

## 17. Escalation Data to Collect

### 17.1 Prisma Access Data

- Tenant name and management model: Panorama or Strata Cloud Manager
- Prisma Access version or Cloud Services plugin version
- Service connection name and remote network name
- Mobile user location and source user
- Source IP, destination IP/FQDN, timestamp, and timezone
- Traffic log entries, system log entries, and NAT rule match
- Security rule match and session end reason
- Routing Information output (route table, BGP status)
- BGP Status, RIB-In, Local RIB, and RIB-Out where available
- Config Status, Tunnel Status, and BGP Status

### 17.2 CPE / Data Center Data

- BGP neighbor state
- BGP advertised, received, accepted, and installed routes
- Forwarding table entry for destination and return path
- Route-map and prefix-list configuration
- NAT policy and security policy logs
- Packet capture if available
- IPsec SA status and tunnel monitor state
- Recent routing, SD-WAN, NAT, or policy changes

---

## 18. Best Practices Summary

### 18.1 Architecture and Design

- Always configure a service connection if mobile users need to reach remote network users or HQ private apps
- Use BGP over static routing for service connections and remote networks in production environments. Static routes do not adapt to failure.
- Assign **unique BGP AS numbers** to each CPE/router. Reusing an AS causes AS_PATH loop prevention to drop routes.
- Summarize routes at the edge. Advertise the most specific useful prefix. Avoid /8 or broader summaries.
- Plan the Mobile User IP Pool as a dedicated, non-overlapping range. Advertise this pool from Prisma Access to HQ via BGP so HQ devices have return routes.

### 18.2 NAT Policy

- Apply **no-NAT rules** for traffic destined to private apps via service connections to preserve User-ID and Device-ID
- SNAT is appropriate for internet-bound traffic only, applied after the no-NAT rules are matched for internal destinations
- Document all NAT rules with descriptions referencing the intended traffic flow

### 18.3 Security Policy Zoning

- Define separate zones for Mobile Users, Remote Networks, Corporate (HQ), and Internet in Prisma Access
- Intra-zone traffic must have an explicit policy permitting it — Prisma Access does **not** implicitly permit intra-zone traffic
- Use App-ID and User-ID in security policies for private app access rather than relying solely on IP-based rules

### 18.4 Monitoring and Alerting

- Configure tunnel monitoring alerts for all service connections. A silent SC failure will be reported as an application outage hours later.
- Monitor BGP prefix counts. A sudden drop to zero prefixes from a peer indicates a configuration change or routing policy filter taking effect.
- Use Prisma Access Insights (available in Cloud Manager) for historical traffic flow data, bandwidth trends, and session analytics.

---

## 19. Quick Reference Checklist

**Mobile Users Cannot Reach Private Apps:**
- [ ] Service connection tunnel is UP (Phase 1 and Phase 2)
- [ ] Service connection BGP session is Established
- [ ] HQ is advertising the app subnet to Prisma Access via BGP
- [ ] Route for app subnet present in Prisma Access routing table
- [ ] Security policy permits Mobile User zone → Corporate zone
- [ ] No unexpected SNAT applied to service-connection-bound traffic
- [ ] HQ firewall permits traffic arriving from Prisma Access tunnel IP
- [ ] HQ has a return route for the Mobile User IP Pool

**Remote Network Tunnel Up, Routes Missing:**
- [ ] Remote network configuration specifies correct subnets (static) or BGP is enabled
- [ ] CPE BGP session Established with Prisma Access
- [ ] CPE advertising correct prefixes (not /32 hosts, not 0.0.0.0/0)
- [ ] **Do Not Export Routes** is NOT enabled unless intentionally isolating this site
- [ ] Prisma Access routing table shows branch prefixes after BGP convergence
- [ ] CPE has routes for Mobile User Pool and HQ subnets pointing to Prisma Access tunnel

**BGP Troubleshooting:**
- [ ] Tunnel (IPsec) is UP before BGP can establish
- [ ] AS numbers match on both sides
- [ ] Peer IPs match tunnel interface IPs (not physical interface IPs)
- [ ] MD5 authentication keys match (if configured)
- [ ] Prefix lists not filtering all routes in or out
- [ ] Hold-time and keepalive timers compatible between peers
- [ ] No AS_PATH loop (unique AS per site)

---

## 20. Final Diagnostic Rule

Do not troubleshoot Prisma Access routing as simply "VPN up or VPN down." Troubleshoot it as a **deterministic chain of forwarding requirements:**

1. Can the source **enter** Prisma Access?
2. Does Prisma Access **know where the destination is**?
3. Does the destination side know **how to return traffic**?
4. Did BGP advertise the **right prefixes at the right prefix length**?
5. Did **static routing override BGP**?
6. Did **policy allow** the real path?
7. Did **NAT preserve or destroy** identity context?
8. Did Prisma Access **select the intended** service connection or remote network path?

If every condition is true, the flow works. If one condition is false, the flow fails. The job of troubleshooting is to identify the **first false condition** in the chain.

---

*End of Article KB-PA-ROUTING-001*
