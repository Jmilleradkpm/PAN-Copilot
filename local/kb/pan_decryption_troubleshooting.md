# KB: SSL/TLS Decryption Troubleshooting on Palo Alto Networks NGFW

**Article ID:** KB-PAN-DEC-001
**Applies to:** PAN-OS 10.0 / 10.1 / 10.2 / 11.0 / 11.1 / 11.2; Panorama-managed and standalone NGFW; Prisma Access Cloud-Managed (where noted)
**Audience:** Security/Network engineers responsible for SSL Forward Proxy, SSL Inbound Inspection, or SSH Proxy
**Severity rating:** P2 (broken apps), P3 (partial breakage), informational (proactive hardening)

---

## 1. Summary

SSL/TLS decryption is consistently the largest source of long-tail support tickets on Palo Alto NGFWs. Symptoms range from a single SaaS app refusing to load to entire user populations losing access to a banking site. The root causes almost always fall into one of nine categories — and the diagnostic path is the same regardless of which category you're in.

This article gives you:

1. A repeatable diagnostic workflow ("where do I even start")
2. The nine failure modes that cover ~95% of decryption tickets, each with detection logic and a fix
3. CLI cheat-sheet for decryption troubleshooting
4. A defensible methodology for building a no-decrypt list
5. A phased rollout strategy that prevents these tickets in the first place

---

## 2. Background: Why Decryption Breaks (and Why It's Hard)

Decryption is a man-in-the-middle operation. The firewall presents a forged certificate to the client, terminates the original session with the server, and re-encrypts in both directions. Anything that breaks the trust model on **either** side breaks the session — and modern apps deliberately try to detect MITM:

- **Cert pinning** — apps ship with the legitimate server's public key hash baked in. If the firewall presents a different cert (even a valid one), the app refuses to connect.
- **TLS 1.3** — encrypted handshakes (encrypted SNI, encrypted certificate, ECH) reduce visibility into what failed.
- **QUIC/HTTP3** — runs on UDP/443; the firewall cannot decrypt QUIC. Apps fall back to TCP only if QUIC is blocked.
- **Mutual TLS (mTLS)** — the server requires a client cert. Forward Proxy can't supply one for the client.
- **Cert chain hygiene** — many origin servers serve incomplete chains; browsers fix this with AIA-fetching, but PAN-OS does not by default for forward proxy.
- **Revocation** — the firewall must reach OCSP/CRL endpoints; if it can't, you choose between failing closed (breaks apps) or failing open (weakens security).

The job is rarely "make decryption work for everything." The job is **decrypt what you can, exclude what you must, and prove which bucket each app is in.**

---

## 3. Decryption Modes Quick Reference

| Mode | Use Case | Cert Source | Common Failure Pattern |
|------|----------|-------------|------------------------|
| **SSL Forward Proxy** | Outbound user → internet TLS | Forward Trust + Forward Untrust CAs on FW | Cert pinning, incomplete chains, mTLS, QUIC |
| **SSL Inbound Inspection** | Inbound to internal server | Server's actual cert + private key on FW | Wrong cert/key uploaded, ECDHE PFS without RSA fallback |
| **SSH Proxy** | Outbound SSH | Auto-generated | Host key changed alarms |
| **No-Decrypt rule** | Privacy/compliance/breakage exclusion | None (passes through) | Still applies cert validation if profile attached |

Most tickets are **SSL Forward Proxy**. This article focuses there, but Section 7.5 covers Inbound Inspection.

---

## 4. The Diagnostic Workflow

Use this order. Skipping steps is how you spend three hours on a fifteen-minute fix.

### Step 1 — Confirm the user/app is actually hitting a decrypt rule

In the GUI: **Monitor → Logs → Traffic**, filter on the user/source IP, then look at the **Decrypted** column (you may need to enable it via the column picker). If it's blank or "no", the session never matched a decrypt policy — the problem isn't decryption, it's policy/routing/NAT.

CLI equivalent:

```
show session all filter source <client-ip> destination <dest-ip>
show session id <id>
```

Look for `decrypt mirror : False`, `decrypted : True/False`, and the `application` field. If it shows `incomplete` or `insufficient-data`, the TLS handshake never completed.

### Step 2 — Read the Decryption Log (PAN-OS 10.0+)

**Monitor → Logs → Decryption.** This was the single biggest improvement in PAN-OS 10.0 for this work. Every TLS session that touched a decryption policy (decrypt **or** no-decrypt) shows up here with:

- `Error Index` and a human-readable failure reason
- TLS version, cipher suite, key exchange
- Server certificate fingerprint, CN, SAN, issuer
- Whether the chain was complete
- SNI

If you only do one thing: **enable decryption logging on every decrypt and no-decrypt rule.** It's not on by default. On the rule: `Options → Log Successful TLS Handshakes` and `Log Unsuccessful TLS Handshakes`.

### Step 3 — Check Decryption Failure Reasons

ACC has a dedicated widget: **ACC → SSL Activity → Decryption Failure Reasons**. This aggregates the same data as the Decryption log but groups by reason — invaluable when you're hunting "what's actually broken in production today" rather than chasing a single ticket.

The reasons you will see most often (verbatim from the firewall):

- `Resource not available`
- `Unsupported cipher`
- `Unsupported version`
- `Unsupported ECDSA curve`
- `Certificate expired`
- `Untrusted issuer`
- `Certificate not yet valid`
- `Unknown certificate status` (OCSP/CRL fetch failed)
- `Pinned certificate` (only inferable; PAN-OS doesn't always label this explicitly)
- `Client authentication required` (mTLS)
- `SNI mismatch`

### Step 4 — Global counters

When the decryption log doesn't tell you enough, drop to counters. This is the single most useful CLI command for decryption work:

```
show counter global filter aspect ssl delta yes
```

Run it, reproduce the failure, run it again. The deltas tell you what failed in the SSL/TLS engine. Counters worth knowing by name:

| Counter | Meaning |
|---------|---------|
| `proxy_ssl_decrypted_packet` | Successful decryption packets |
| `proxy_decrypt_pkt_drop_no_resource` | Out of decryption resources (sized incorrectly or PBP undersized) |
| `ssl_proxy_drop_unsupported_protocol` | Client/server forced a TLS version not enabled in your profile |
| `ssl_proxy_drop_unsupported_cipher` | Cipher suite not in your decryption profile |
| `proxy_no_resource` | Hardware/session-table exhaustion |
| `flow_tcp_non_syn_drop` | TCP state mismatch — often asymmetric routing combined with decrypt |

### Step 5 — Packet capture

Last resort, but definitive. Set up filters and stages:

```
debug dataplane packet-diag set filter match source <client> destination <server>
debug dataplane packet-diag set filter on
debug dataplane packet-diag set capture stage receive file rx.pcap
debug dataplane packet-diag set capture stage transmit file tx.pcap
debug dataplane packet-diag set capture on
```

Reproduce, then `set capture off`. Files land in `/var/tmp/` (export via SCP). Open in Wireshark and look at the TLS handshake:

- **Client Hello** — what versions/ciphers/SNI did the client offer?
- **Server Hello** — what did the server (or firewall, in forward proxy) pick?
- **Certificate** — chain complete? Issuer trusted by client?
- **Alert** — the alert code tells you everything: `bad_certificate (42)`, `unknown_ca (48)`, `certificate_expired (45)`, `protocol_version (70)`, `handshake_failure (40)`, `unsupported_certificate (43)`, `certificate_unknown (46)`.

---

## 5. The Nine Failure Modes

Each section below: **detection signature → root cause → fix**.

### 5.1 Incomplete certificate chain (server-side)

**Detection:** Decryption log shows `Untrusted issuer` or `Certificate chain incomplete`. Browser direct-to-site works (browser fetched the intermediate via AIA); through firewall, it fails.

**Root cause:** The origin server only sends its leaf certificate; the intermediate is not in the firewall's trusted-CA store.

**Fix options:**

1. **Preferred:** Manually import the missing intermediate(s) into **Device → Certificate Management → Certificates** and mark as Trusted Root CA.
2. **Enable AIA chain construction** (PAN-OS 10.1+): **Device → Certificate Management → Certificate Profile → Use CRL / Use OCSP** and enable AIA fetching at the system level. Note: requires the firewall to reach the AIA URL (typically port 80 outbound).
3. Tell the application/site owner to fix their chain. (Will not happen.)

**Verification:** `show system setting ssl-decrypt certificate-cache` and check the chain is now resolved.

### 5.2 Forward Trust CA not installed on clients

**Detection:** Browser shows `NET::ERR_CERT_AUTHORITY_INVALID` (Chrome) or `MOZILLA_PKIX_ERROR_MITM_DETECTED` (Firefox in some builds). Decryption log shows handshake completed on the firewall side, but client tears down. Affects **all** decrypted sites uniformly, not one app.

**Root cause:** The Forward Trust certificate the firewall uses to sign forged certs is not in the client's trust store.

**Fix:**

- **Windows domain-joined:** Push via GPO → Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies → Trusted Root Certification Authorities. Verify with `certutil -store -enterprise root`.
- **macOS managed:** Profile via Jamf/Intune/Kandji. Must be marked "Always Trust" in Keychain (System keychain, not login).
- **iOS/Android:** Push via MDM as a configuration profile + (iOS) toggle in Settings → General → About → Certificate Trust Settings. **Required step on iOS — easy to miss.**
- **Firefox:** Does not use OS trust store by default. Either enable `security.enterprise_roots.enabled = true` or distribute via policies.json.
- **BYOD:** You will not solve this for unmanaged devices. Either use captive-portal-installable cert or exclude BYOD source IPs from decryption.

### 5.3 Unsupported cipher suite

**Detection:** Decryption log: `Unsupported cipher`. Counter `ssl_proxy_drop_unsupported_cipher` increments. Often correlates with very modern apps (TLS 1.3 cipher) or very legacy apps (TLS 1.0 RC4-MD5 type).

**Root cause:** Your **Decryption Profile → SSL Forward Proxy → SSL Protocol Settings** doesn't permit the negotiated cipher.

**Fix:**

- **Objects → Decryption → Decryption Profile → SSL Protocol Settings**:
  - Min TLS version: 1.2 (1.3 if you have full TLS 1.3 decryption support — PAN-OS 10.2+ for forward proxy)
  - Max TLS version: max
  - Key Exchange Algorithms: enable RSA, DHE, ECDHE
  - Encryption Algorithms: AES-128-CBC, AES-256-CBC, AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 (10.2+)
  - Authentication Algorithms: SHA-256, SHA-384

**Hard-fail policy:** Resist the urge to enable 3DES or RC4 just to fix one app. Add a no-decrypt exception for that app instead. Loosening cipher rules globally to fix one ticket is how decryption hygiene rots.

### 5.4 Weak / unsupported TLS protocol version

**Detection:** Decryption log: `Unsupported version`. Wireshark Client Hello / Server Hello disagree on version.

**Root cause:** Either profile blocks it, or one side doesn't support what the other offered.

**Fix:** Same Decryption Profile → SSL Protocol Settings. Set Min Version to 1.2 in 2026; **do not** drop to 1.0/1.1 to fix legacy hosts. Exclude legacy hosts via no-decrypt rule and treat them as a remediation backlog item.

**Note for TLS 1.3:** PAN-OS forward proxy support for TLS 1.3 was incomplete pre-10.2. On 10.2+, TLS 1.3 forward proxy works but ECH (Encrypted Client Hello) and ESNI traffic still cannot be decrypted — those sessions get classified as TLS 1.3 and dropped or no-decrypted depending on your profile setting `Block sessions with client authentication`.

### 5.5 Revoked / unknown certificate status

**Detection:** Decryption log: `Unknown certificate status` or `Certificate revoked`. Often intermittent — works when OCSP responder is reachable, fails when it isn't.

**Root cause:** Decryption profile has `Block sessions with expired certificates` and `Block sessions with unknown certificate status` enabled, and the firewall cannot reach OCSP/CRL endpoints. Common failure on networks where the firewall management plane has restricted internet egress.

**Fix:**

1. Confirm the firewall MGT (or service-route-configured interface) can reach the issuer's OCSP/CRL URLs. Common ones: `ocsp.digicert.com`, `crl3.digicert.com`, `ocsp.pki.goog`, `r3.o.lencr.org`.
2. Configure a service route: **Device → Setup → Services → Service Route Configuration** — point CRL/OCSP traffic out a dataplane interface with internet access.
3. Last resort: uncheck `Block sessions with unknown certificate status` in the decryption profile. Document the risk acceptance.
4. If you use a corporate proxy for outbound, configure it under **Device → Setup → Services → Proxy Server**.

### 5.6 Certificate pinning (Teams, Zoom, banking apps, mobile apps)

**Detection:** Specific app fails consistently. Other apps on same client work fine. Decryption log shows handshake completed successfully on firewall side. No alert in firewall logs from the client. App often shows generic "cannot connect" error. Sometimes only mobile clients of the app fail while the web version works.

**Root cause:** App ships with hardcoded public key hash of the legitimate server. The firewall's forged cert doesn't match. App refuses to connect — and refuses to tell you why.

**Fix:** **You cannot decrypt pinned apps.** You must exclude them.

- Use the **PAN-DB SSL Decryption Exclusion list**: **Objects → Decryption → SSL Decryption Exclusion**. PAN updates this list with content updates; it covers known-pinned hosts including most Microsoft 365 services, Zoom, Apple services, Dropbox, and major banking sites.
- For apps not on the PAN-DB list, build a custom URL category and add to a no-decrypt rule, or use FQDN-based address objects targeting the SNI.
- **Microsoft 365:** Use the official MS optimize/allow/default endpoint list (https://endpoints.office.com). The "Optimize" category should always be no-decrypt + bypass-content-inspection. "Allow" should be no-decrypt. "Default" can be decrypted.
- **Zoom:** No-decrypt `*.zoom.us`, `*.zoomgov.com`, plus their media servers (ranges in their docs).
- **Banking:** No-decrypt the URL category `financial-services` outright — not worth the risk and most jurisdictions impose privacy obligations on financial-data inspection anyway.

### 5.7 Mutual TLS / client certificate authentication required

**Detection:** Decryption log: `Client authentication required`. Server explicitly requests a client cert during handshake.

**Root cause:** The original session uses mTLS. SSL Forward Proxy cannot present a client cert on behalf of the user — the firewall doesn't have it.

**Fix:** Add the destination to a no-decrypt rule. There is no workaround for forward proxy. (Inbound inspection can support mTLS in some configurations — see TechDocs `ssl-inbound-inspection-with-client-auth`.)

Common offenders: developer-facing APIs, federal/government endpoints, healthcare HL7 endpoints, some EDI/B2B integrations.

### 5.8 SNI mismatch / wildcard / hostname issues

**Detection:** Decryption log: `SNI mismatch` or browser shows cert error pointing to wrong CN.

**Root cause:** Client sends SNI `app.example.com`, server returns cert valid for `*.example.com` or `example.com`. Or the firewall forged a cert with the wrong SAN. Or no SNI was sent at all (older clients).

**Fix:**

- For "no SNI" cases: most modern apps send SNI. If you have a legacy app that doesn't, exclude its destination IP via no-decrypt.
- For forged-cert SAN mismatch (rare since 10.0): check **Device → Certificate Management → Certificate Profile** used for forward trust. Upgrade if you're on a pre-10.0 PAN-OS; this was a known issue area.

### 5.9 QUIC / HTTP/3 bypassing decryption

**Detection:** Browsers (especially Chrome) connect to Google, YouTube, Cloudflare-fronted sites, and you see no decryption log entries. Traffic logs show `quic` application on UDP/443. The firewall sees the metadata but **cannot inspect payload — QUIC is not decryptable on PAN-OS as of PAN-OS 11.2**.

**Root cause:** QUIC encrypts almost everything including the handshake. Even with a MITM cert, you can't decrypt it.

**Fix:** **Block QUIC.** Browsers fall back to TCP/TLS automatically.

- Create a security rule **above** your allow rules: deny `application = quic` in any zone-to-zone path that includes user traffic.
- For belt-and-suspenders: deny `service = service-quic` (UDP/443) outbound for user zones. Optional but ensures a non-Application-aware engine catches it.
- Verify: traffic logs should now show `ssl` / `web-browsing` for the same destinations as users connect via TLS instead of QUIC.

**Performance impact:** Negligible for users; modern browsers handle the fallback transparently. Don't skip this — it's the single biggest decryption blind spot in most environments.

---

## 6. Building a Defensible No-Decrypt List

A good no-decrypt list is built **bottom-up by category, not by ticket.**

**Tier 1 — Always no-decrypt (legal/regulatory/operational):**

- URL Category `financial-services`
- URL Category `health-and-medicine`
- URL Category `government`
- URL Category `military`
- PAN-DB SSL Decryption Exclusion list (predefined, content-updated)
- Microsoft 365 Optimize and Allow endpoints (consume Microsoft's published list via External Dynamic List from `https://endpoints.office.com/endpoints/worldwide?clientrequestid=...`)

**Tier 2 — Pinned apps (operational reality):**

- `*.zoom.us`, `*.zoomgov.com`
- Apple services (`*.apple.com`, `*.icloud.com`, `*.itunes.apple.com`, push.apple.com)
- Major MDM endpoints (Jamf, Intune, Workspace ONE)
- Dropbox, Box (cert-pinned mobile clients)
- Banking apps your users actually use (collect from network telemetry, not assumption)

**Tier 3 — Privacy/HR-policy:**

- URL Category `personal-storage` (employee personal Dropbox/Drive — debatable, depends on policy)
- HR/payroll SaaS specific to your stack

**What goes in a Decryption Profile attached to no-decrypt rules:**

Even on no-decrypt rules, attach a profile that **still** validates server certs (block expired, block untrusted issuer). This catches SSL-stripping attacks and bad TLS hygiene without breaking the app.

---

## 7. Phased Rollout / Avoiding the Ticket Storm

If you're standing up decryption from scratch (or recovering after disabling it), do not flip it on for everyone at once. Do this:

**Phase 0 — Pre-flight (1–2 weeks):**

1. Push Forward Trust CA to all managed endpoints. Verify on samples from each platform (Win, Mac, iOS, Android, Linux).
2. Create the no-decrypt list (Section 6). Deploy this **first**, with action `no-decrypt` and logging enabled.
3. Block QUIC.
4. Stage decryption profiles but don't reference them yet.

**Phase 1 — Visibility-only (1 week):**

Create a decryption rule with action `decrypt` for a small pilot group (10–20 users, ideally including an exec on each platform — they generate the right kind of feedback fast). Logging on. Walk the Decryption log every morning and triage.

**Phase 2 — Expand by zone/department:**

Roll department by department. Each rollout, watch ACC → Decryption Failure Reasons for 48 hours. Add to the no-decrypt list as needed. Resist the urge to weaken the decryption profile.

**Phase 3 — Tighten:**

After steady state, raise minimum TLS to 1.2, drop weak ciphers, enable strict cert validation (block expired, block untrusted, block unknown status). This is where you go from "decryption works" to "decryption is doing actual security work."

---

## 8. CLI Cheat Sheet

```
# Is this session being decrypted?
show session id <session-id>

# What's the SSL/TLS engine doing right now?
show counter global filter aspect ssl delta yes

# Drops with decryption-related severity
show counter global filter delta yes severity drop

# Decryption certificate cache state
show system setting ssl-decrypt certificate-cache
show system setting ssl-decrypt exclude-cache

# What's my current SSL Forward Proxy CA?
show system setting ssl-decrypt setting

# PAN-DB SSL Decryption Exclusion list (predefined, updated by content)
request system external-list show name panw-ssl-decryption-exclude-cn-list

# Memory/resource pressure on dataplane
show running resource-monitor

# Live SSL session count
show session info | match ssl

# Test cert chain reachability (to OCSP/CRL endpoints)
ping host ocsp.digicert.com
test scep-status <profile-name>     # if using SCEP for forward trust

# Packet capture for a specific flow
debug dataplane packet-diag set filter match source <ip> destination <ip>
debug dataplane packet-diag set filter on
debug dataplane packet-diag set capture stage receive file rx
debug dataplane packet-diag set capture stage transmit file tx
debug dataplane packet-diag set capture on
# reproduce
debug dataplane packet-diag set capture off
debug dataplane packet-diag clear filter-marked-session all
# files in /var/tmp/, retrieve with: scp export filter-pcap from rx to <host>
```

---

## 9. Decryption Profile — Recommended Baseline (PAN-OS 11.x)

```
Objects → Decryption → Decryption Profile → "DEC-Forward-Proxy-Strict"

SSL Forward Proxy:
  Server Certificate Verification:
    [x] Block sessions with expired certificates
    [x] Block sessions with untrusted issuers
    [x] Block sessions with unknown certificate status   # only after OCSP/CRL routing verified
    [x] Block sessions on certificate status check timeout
    [x] Restrict certificate extensions
    [ ] Append certificate's CN value to SAN extension   # enable for legacy compatibility
  Unsupported Mode Checks:
    [x] Block sessions with unsupported versions
    [x] Block sessions with unsupported cipher suites
    [x] Block sessions with client authentication        # forces no-decrypt fallback for mTLS
  Failure Checks:
    [x] Block sessions if resources not available
    [x] Block sessions if HSM not available              # if HSM is in use
  Client Extensions:
    [x] Strip ALPN

SSL Protocol Settings:
  Min Version: TLSv1.2
  Max Version: Max (TLSv1.3)
  Key Exchange: RSA, DHE, ECDHE
  Encryption: AES128-CBC, AES256-CBC, AES128-GCM, AES256-GCM, ChaCha20-Poly1305
  Authentication: SHA256, SHA384
```

For no-decrypt rules, use a separate profile that **still** validates server certs but doesn't enforce protocol/cipher rules:

```
"DEC-No-Decrypt-Validate"
No Decryption tab:
  [x] Block sessions with expired certificates
  [x] Block sessions with untrusted issuers
```

---

## 10. When to Open a TAC Case

You've done your job; now collect:

1. PAN-OS version: `show system info | match version`
2. Tech support file: **Device → Support → Generate Tech Support File**
3. Decryption log export filtered to the affected user/destination, in CSV
4. Packet captures (rx + tx, both stages) covering a reproducible failure
5. Output of `show counter global filter aspect ssl delta yes` before/after repro
6. The full URL/FQDN, the application name (PAN App-ID), and at least one example client IP/MAC
7. Whether the issue is universal or scoped to a platform/OS/browser

TAC will resolve far faster with this in hand than with "decryption is broken for some users."

---

## 11. References

- Palo Alto Networks TechDocs: *Decryption* (current PAN-OS) — `https://docs.paloaltonetworks.com/network-security/decryption`
- KB 210699 — *Resource List: SSL Decryption Configuring and Troubleshooting*
- PAN-DB SSL Decryption Exclusion list: built-in, view via Objects → External Dynamic Lists
- Microsoft 365 endpoint list: `https://endpoints.office.com`
- Best Practice Assessment (BPA): run periodically; flags decryption profile weaknesses
- LIVEcommunity → SSL Decryption discussions

---

## 12. Revision History

| Version | Date | Author | Notes |
|---------|------|--------|-------|
| 1.0 | 2026-05-10 | Initial publication | Covers PAN-OS 10.0–11.2 |
