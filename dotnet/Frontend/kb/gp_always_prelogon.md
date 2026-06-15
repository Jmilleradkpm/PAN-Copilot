# KB-GP-PRELOGON-001 — GlobalProtect Always Pre-Logon (Always On): Complete Setup Guide
**Using Certificates Generated Directly on the Palo Alto Networks Firewall**

| Field | Value |
|---|---|
| KB ID | KB-GP-PRELOGON-001 |
| Version | 1.0 |
| Platform | PAN-OS 10.x / 11.x |
| Author | Network Engineering |
| Last Updated | April 2026 |
| Status | Active / Production |

---

## 1. Overview

GlobalProtect Always Pre-Logon (Always On with Pre-Logon) establishes a secure IPsec/SSL VPN tunnel **before** the Windows or macOS user interactively logs in. The tunnel is maintained throughout the entire device lifecycle — from boot, through user logon, and during active sessions — ensuring corporate security policies, threat prevention, and DNS resolution are enforced at all times with no unprotected window.

This guide covers end-to-end configuration using certificates generated **natively on the Palo Alto Networks firewall**, eliminating the need for an external CA or PKI repository.

### 1.1 How Pre-Logon Works

1. Endpoint boots → GlobalProtect agent detects no user is logged in
2. Agent uses a **machine-level certificate** (in Windows Local Computer store or macOS System Keychain) to authenticate to the Portal, then the Gateway
3. Machine certificate is signed by the Root CA on the firewall
4. Once the user logs in, the agent transitions from machine-cert auth to user-based auth (or stays on machine cert — depends on Connect Method)
5. With **Always On** selected, users cannot manually disconnect or disable GlobalProtect

### 1.2 Key Terminology

| Term | Definition |
|---|---|
| Pre-Logon | VPN tunnel established using a machine certificate before interactive user logon |
| Always On | Agent connect method that prevents users from disabling or disconnecting the tunnel |
| Portal | HTTPS endpoint that distributes agent configs and certificates to endpoints |
| Gateway | IPsec/SSL endpoint that terminates the VPN tunnel from endpoints |
| Machine Certificate | X.509 cert in the device's System certificate store, identifying the machine |
| Root CA | Self-signed Certificate Authority on the firewall that signs machine certificates |
| Certificate Profile | PAN-OS object defining which CAs are trusted for authenticating VPN clients |
| Pre-Logon Tunnel | VPN session established with machine-cert auth before user logon |
| User Tunnel | VPN session established after user logon |

### 1.3 Architecture Diagram (Logical Flow)

```
Device powers on
  → GlobalProtect agent starts as a Windows Service / LaunchDaemon
  → Agent connects to GP Portal (HTTPS 443) using machine certificate
  → Portal validates machine cert against Certificate Profile → returns gateway list + agent config
  → Agent connects to GP Gateway (IPsec UDP 4501 or SSL 443) using machine certificate
  → Gateway validates machine cert → IPsec/SSL tunnel established (Pre-Logon tunnel)
  → User logs in to Windows/macOS → agent may re-auth with user credentials (if configured)
  → Always On enforced — user cannot disconnect or disable the agent
```

> **WARNING:** Always On completely removes the user's ability to disconnect GlobalProtect. Ensure you have a documented exception process (e.g., break-glass local admin procedure) before deploying Always On to production.

---

## 2. Prerequisites

### 2.1 Licensing
- GlobalProtect Gateway license applied to the firewall (required for gateway functionality)
- GlobalProtect Portal does not require a separate license on most platforms
- Verify: **Device > Licenses** — confirm GlobalProtect is listed and not expired

> **NOTE:** On Prisma Access deployments, licensing is managed through the Prisma Access portal, not the on-premises firewall. This guide covers on-premises NGFW deployments.

### 2.2 PAN-OS Version
- PAN-OS 9.1 or later strongly recommended
- PAN-OS 10.x or 11.x preferred for full feature support
- GlobalProtect agent version must match or exceed the minimum required by the portal config

### 2.3 Network Requirements
- Routable IP address dedicated to GlobalProtect Portal (can share an existing interface)
- Routable IP address dedicated to GlobalProtect Gateway (can be same interface as portal)
- Inbound firewall rules permitting TCP/443 and UDP/4501 to the gateway IP from the internet
- Internal DNS record resolving the portal/gateway FQDN (e.g., `vpn.example.com`) to the public IP
- IP pool range for GlobalProtect tunnel addresses (must not overlap existing subnets)

### 2.4 Endpoint Requirements
- Windows 10/11 (64-bit) or macOS 12+
- GlobalProtect agent installed (MSI or PKG) — version 6.x recommended
- Domain-joined (for GPO cert deployment) or managed via MDM
- Local administrator rights required during initial agent installation

### 2.5 Firewall Interface Configuration

| Field | Value |
|---|---|
| Portal / Gateway Interface | `ethernet1/1` (or any external-facing interface) |
| Interface IP | `<GATEWAY-PUBLIC-IP>/24` (replace with your public IP) |
| Interface Zone | Untrust |
| Tunnel Interface | `tunnel.1` (created in Section 5) |
| Tunnel Zone | VPN (create in Section 5) |
| Internal Interface/Zone | `ethernet1/2` / Trust |

---

## 3. Certificate Infrastructure — Firewall-Generated Certificates

Three certificate objects are created:
1. **Root CA Certificate** — self-signed authority that signs all other certificates
2. **Portal / Gateway Server Certificate** — presented to clients when connecting
3. **Machine Certificate** — issued to each endpoint

> **NOTE:** Certificates generated on the firewall are self-signed. Clients only trust this CA after you deploy the Root CA certificate to their Trusted Root Certification Authorities store (covered in Section 10).

### 3.1 Create the Root Certificate Authority

**Navigation:** Device > Certificate Management > Certificates > Generate

| Field | Value |
|---|---|
| Certificate Name | `GP-Root-CA` |
| Common Name (CN) | `GlobalProtect Root CA` (or your organization name) |
| Certificate Authority | **Check this box** — marks the cert as a CA certificate |
| Signed By | External Authority (Self Signed) |
| Key Type | RSA |
| Key Size (Bits) | 4096 |
| Digest Algorithm | SHA-384 (minimum SHA-256; SHA-384 recommended) |
| Expiration (days) | 3650 (10 years — appropriate for a Root CA) |
| Country (C) | Your two-letter country code |
| Organization (O) | Your organization name |
| Organizational Unit (OU) | Network Engineering |

Click **Generate**. PAN-OS generates a 4096-bit RSA key pair and self-signed CA certificate.

> **TIP:** Do not export or install the Root CA private key anywhere outside the firewall. You only export the public certificate (CRT) for deployment to endpoints.

### 3.2 Create the Portal and Gateway Server Certificate

**Navigation:** Device > Certificate Management > Certificates > Generate

| Field | Value |
|---|---|
| Certificate Name | `GP-Server-Cert` |
| Common Name (CN) | `vpn.example.com` (must match the FQDN clients will resolve) |
| Certificate Authority | Leave unchecked — end-entity certificate |
| Signed By | `GP-Root-CA` |
| Key Type | RSA |
| Key Size (Bits) | 2048 |
| Digest Algorithm | SHA-256 |
| Expiration (days) | 730 (2 years) |

**Add Subject Alternative Names (SANs) — Critical:**
- Type: IP — Value: `<GATEWAY-PUBLIC-IP>` (your portal/gateway public IP)
- Type: DNS — Value: `vpn.example.com` (your portal/gateway FQDN)

> **WARNING:** If you skip SANs, modern browsers and the GlobalProtect agent may reject the certificate with an SSL error, preventing clients from connecting to the portal. Both IP and FQDN SANs are required.

### 3.3 Create the Machine Certificate (Single Device)

**Navigation:** Device > Certificate Management > Certificates > Generate

| Field | Value |
|---|---|
| Certificate Name | `GP-Machine-HOSTNAME` (replace HOSTNAME with device name) |
| Common Name (CN) | `HOSTNAME.example.com` (FQDN of the specific endpoint) |
| Certificate Authority | Leave unchecked |
| Signed By | `GP-Root-CA` |
| Key Type | RSA |
| Key Size (Bits) | 2048 |
| Digest Algorithm | SHA-256 |
| Expiration (days) | 365 (1 year — rotate annually) |
| Organizational Unit (OU) | Managed Endpoints |

**Export the machine certificate WITH the private key:**

| Field | Value |
|---|---|
| File Format | PKCS12 (.p12) — bundles cert + private key |
| Include Private Key | Yes |
| Passphrase | `<CERTIFICATE-PASSPHRASE>` (set a strong passphrase; required during endpoint import) |

> **WARNING:** The .p12 file contains the private key. Transfer via encrypted channel only. Delete the file from intermediate storage after successful installation on the endpoint.

### 3.4 Export the Root CA Certificate for Endpoint Deployment

**Navigation:** Device > Certificate Management > Certificates

Click `GP-Root-CA` → Export:

| Field | Value |
|---|---|
| File Format | Base64 Encoded Certificate (PEM) |
| Include Private Key | **No** — do NOT export the private key |

Save as `GP-Root-CA.cer`. This file is deployed to all endpoints in Section 10.

### 3.5 Create the Certificate Profile for Client Authentication

**Navigation:** Device > Certificate Management > Certificate Profile > Add

| Field | Value |
|---|---|
| Name | `GP-Machine-CertProfile` |
| Username Field | Subject — Common Name |
| Domain | `example.com` (your domain — appended to CN for user mapping) |

Under **CA Certificates** tab, click Add:

| Field | Value |
|---|---|
| CA Certificate | `GP-Root-CA` |
| OCSP Verify Client Cert | No (unless OCSP is configured on the firewall) |
| CRL Status | No (unless a CRL distribution point is configured) |

---

## 4. SSL/TLS Service Profile

**Navigation:** Device > Certificate Management > SSL/TLS Service Profile > Add

| Field | Value |
|---|---|
| Name | `GP-SSL-Profile` |
| Certificate | `GP-Server-Cert` |
| Min TLS Version | TLS 1.2 |
| Max TLS Version | Max (allows TLS 1.3) |
| TLS 1.3 | Allowed |

---

## 5. Tunnel Interface and VPN Zone

### 5.1 Create the Tunnel Interface

**Navigation:** Network > Interfaces > Tunnel > Add

| Field | Value |
|---|---|
| Interface Name | `tunnel.1` |
| Virtual Router | `default` (or the VR used by your external interface) |
| Security Zone | `VPN` (created in Step 5.2) |
| IP Address | Leave blank — GlobalProtect assigns IPs from the IP pool |
| Comment | GlobalProtect Always On VPN Tunnel |

### 5.2 Create the VPN Security Zone

**Navigation:** Network > Zones > Add

| Field | Value |
|---|---|
| Name | `VPN` |
| Type | Layer3 |
| Interfaces | `tunnel.1` |
| Enable User Identification | Yes (required for User-ID with GP tunnels) |

---

## 6. GlobalProtect Gateway Configuration

**Navigation:** Network > GlobalProtect > Gateways > Add

### 6.1 General Tab

| Field | Value |
|---|---|
| Name | `GP-GW-AlwaysOn` |
| Interface | `ethernet1/1` |
| IP Address | `<GATEWAY-PUBLIC-IP>` |
| Authentication | `GP-SSL-Profile` |

### 6.2 Gateway Client Authentication Entry

Click **Add** in the Client Authentication section:

| Field | Value |
|---|---|
| Name | `Cert-Auth-PreLogon` |
| OS | Any |
| Authentication Profile | None (certificate-only) |
| Certificate Profile | `GP-Machine-CertProfile` |
| Allow Authentication With User Credentials OR Client Certificate | Yes |
| Username Label | (Leave blank — shows 'pre-logon' for machine cert sessions) |

### 6.3 Agent Tab — Tunnel Settings

| Field | Value |
|---|---|
| Tunnel Interface | `tunnel.1` |
| Enable IPsec | Yes (use IPsec when possible; falls back to SSL) |
| Enable Keep-Alive | Yes |
| Timeout (sec) | 3600 |

### 6.4 Agent Tab — IP Pool

| Field | Value |
|---|---|
| IP Pool | `<GP-IP-POOL-SUBNET>` (example: /22 or larger depending on user count) |

> **NOTE:** The IP pool must NOT overlap any existing subnets. For 1,000 users a /22 provides 1,022 addresses. Pre-logon machine sessions consume an IP from this pool.

### 6.5 Agent Tab — Network Settings

| Field | Value |
|---|---|
| Inherit from Interface | No — configure manually |
| Primary DNS Server | `<INTERNAL-DNS-PRIMARY>` (your internal DNS resolver) |
| Secondary DNS Server | `<INTERNAL-DNS-SECONDARY>` (secondary internal DNS resolver) |
| DNS Suffix | `example.com` |
| Additional DNS Suffixes | `corp.example.com`, `ad.example.com` |
| Access Route | `0.0.0.0/0` (full-tunnel — all traffic through VPN) |

> **NOTE:** For Always On / Always Pre-Logon, full-tunnel (`0.0.0.0/0`) is the recommended posture. Split tunneling reduces visibility and should only be implemented with explicit security review.

---

## 7. GlobalProtect Portal Configuration

**Navigation:** Network > GlobalProtect > Portals > Add

### 7.1 General Tab

| Field | Value |
|---|---|
| Name | `GP-Portal-AlwaysOn` |
| Interface | `ethernet1/1` |
| IP Address | `<GATEWAY-PUBLIC-IP>` |
| SSL/TLS Service Profile | `GP-SSL-Profile` |

### 7.2 Authentication Tab — Client Authentication

Click **Add** under Client Authentication:

| Field | Value |
|---|---|
| Name | `Portal-Cert-Auth` |
| OS | Any |
| Authentication Profile | None |
| Certificate Profile | `GP-Machine-CertProfile` |
| Allow Authentication with User Credentials OR Client Cert | Yes |

### 7.3 Agent Tab — Agent Configuration

Click **Add** under Agent Configurations.

#### 7.3.1 Authentication Tab (within Agent Config)

| Field | Value |
|---|---|
| Name | `Always-On-Agent-Config` |
| Save User Credentials | Yes — allows smooth user re-auth after pre-logon |
| Allow Authentication with User Credentials OR Client Cert | Yes |
| Certificate Profile | `GP-Machine-CertProfile` |

#### 7.3.2 Internal Tab (within Agent Config)

| Field | Value |
|---|---|
| Internal Host Detection — IP Address | `<INTERNAL-DNS-PRIMARY>` (an IP only reachable on corpnet) |
| Internal Host Detection — Hostname | `internal-check.example.com` (an internal DNS name) |

> **NOTE:** Internal host detection allows GlobalProtect to suppress the VPN tunnel when the endpoint is already on the corporate LAN, avoiding double-encryption. Optional for Always On but reduces unnecessary VPN overhead for on-site users.

#### 7.3.3 External Tab (within Agent Config)

| Field | Value |
|---|---|
| Add Gateway — Address | `vpn.example.com` (FQDN matching the server cert CN) |
| Priority | 1 (highest priority) |
| Manual | No (auto-selected by priority) |

#### 7.3.4 App Tab — Connect Method (CRITICAL)

| Field | Value |
|---|---|
| **Connect Method** | **Pre-logon (Always On)** ← SELECT THIS OPTION |
| Pre-Logon Username | `pre-logon` (literal string — do not change) |
| Allow User to Dismiss Welcome Page | No |
| Allow User to Change Portal Address | No |
| Allow User to Sign Out | **No** — enforces Always On |
| Allow User to Disable GlobalProtect App | **No** — prevents disabling the agent |
| Show System Tray Notifications | Yes (informational only) |
| Display Login Window | Yes |
| Use Single Sign-On | Yes |
| Enforce GlobalProtect Connection for Network Access | Yes — blocks network if GP is not connected |
| Captive Portal Detection | Yes (allows captive portal bypass for initial internet access) |

> **WARNING:** "Connect Method: Pre-logon (Always On)" enables both the pre-logon tunnel AND Always On enforcement simultaneously. Do not confuse with "Pre-logon then On-demand" (allows user disconnect) or "Always On" alone (does not establish a pre-logon machine-cert tunnel).

#### 7.3.5 HIP Data Collection Tab

| Field | Value |
|---|---|
| Collect HIP Data | Yes (recommended for endpoint posture assessment) |
| HIP Data Collection Interval (sec) | 3600 |
| Max Wait Time (sec) | 20 |

### 7.4 Verify Agent Config Ordering

If multiple agent configurations exist, the portal applies the first matching configuration. Ensure `Always-On-Agent-Config` is at the top of the list or configured to match all managed endpoints.

| Field | Value |
|---|---|
| Config Selection Criteria — OS | Any (or limit to Windows/macOS as required) |
| Config Selection Criteria — User / Group | Any (or an AD group for phased rollout) |

---

## 8. Security Policy Configuration

**Navigation:** Policies > Security > Add

### 8.1 Policy 1 — Allow GP Portal and Gateway Access (Untrust → Self)

Handled by the interface Management Profile rather than a security policy. Traffic to the firewall's own IP is processed by the management plane.

**Navigation:** Network > Interfaces > ethernet1/1 > Advanced > Other Info > Management Profile

Enable **GlobalProtect** in the Management Profile — permits TCP/443 and UDP/4501 to the interface IP.

> **NOTE:** If a Management Profile does not exist, create one at: Network > Network Profiles > Interface Mgmt > Add, then assign it to the external interface.

### 8.2 Policy 2 — Allow GP Clients to Reach Internal Resources (VPN → Trust)

| Field | Value |
|---|---|
| Rule Name | `GP-VPN-to-Internal` |
| Rule Type | Universal |
| Source Zone | VPN |
| Source Address | `<GP-IP-POOL-SUBNET>` |
| Source User | Any (or specify AD groups for RBAC) |
| Destination Zone | Trust |
| Destination Address | Any (or restrict to specific internal subnets) |
| Application | any (or restrict for least-privilege) |
| Service | application-default |
| Action | Allow |
| Security Profiles | Apply standard IPS / AV / URL Filtering profiles |
| Log at Session End | Yes |

### 8.3 Policy 3 — Allow GP Clients Internet Access (VPN → Untrust)

| Field | Value |
|---|---|
| Rule Name | `GP-VPN-to-Internet` |
| Source Zone | VPN |
| Source Address | `<GP-IP-POOL-SUBNET>` |
| Destination Zone | Untrust |
| Destination Address | Any |
| Application | any |
| Service | application-default |
| Action | Allow |
| Security Profiles | Full threat prevention: URL Filter, AV, IPS, DNS Security |
| Log at Session End | Yes |

### 8.4 Policy 4 — Allow Pre-Logon Machine Traffic (VPN → Trust) — Optional

Pre-logon machine sessions authenticate as user `pre-logon` before the user logs in.

| Field | Value |
|---|---|
| Rule Name | `GP-PreLogon-Machine` |
| Source Zone | VPN |
| Source User | `pre-logon` (literal — maps to machine-cert sessions) |
| Destination Zone | Trust |
| Destination Address | `<DC-IP-RANGE>` (AD/DNS minimum access) |
| Application | kerberos, msrpc, dns, ldap |
| Action | Allow |

> **TIP:** Restricting pre-logon sessions to only AD/DNS traffic is a security best practice. Full network access should only be granted after the user authenticates. This limits the blast radius if a machine certificate is compromised.

### 8.5 NAT Policy — Source NAT for VPN Client Internet Traffic

**Navigation:** Policies > NAT > Add

| Field | Value |
|---|---|
| Rule Name | `GP-VPN-SNAT` |
| Source Zone | VPN |
| Destination Zone | Untrust |
| Source Address | `<GP-IP-POOL-SUBNET>` |
| Destination Address | Any |
| Translation Type | Dynamic IP And Port |
| Translated Address | Interface Address — `ethernet1/1` |

> **NOTE:** This NAT rule is required for full-tunnel deployments where GP clients browse the internet through the firewall. Without it, return traffic will not route correctly back to GlobalProtect clients.

---

## 9. Commit the Firewall Configuration

Click **Commit** in the upper-right corner of the PAN-OS web interface. Verify all changed objects are listed with no validation errors. Pay particular attention to certificate references and interface assignments.

> **WARNING:** Do not close the browser tab during a commit. If commit errors reference certificates, verify GP-Root-CA and GP-Server-Cert are not expired.
> 
> Check commit status via CLI: `> show jobs all`

---

## 10. Endpoint Certificate Deployment

Endpoints must have two certificates before Always Pre-Logon will function:
1. **GP-Root-CA.cer** — installed in Trusted Root Certification Authorities store (Computer account)
2. **GP-Machine-HOSTNAME.p12** — installed in Personal certificate store (Computer account)

### 10.1 Deploy Root CA via Group Policy (Recommended)

1. Copy `GP-Root-CA.cer` to a location accessible from the Domain Controller (e.g., `\\<DOMAIN-CONTROLLER>\SYSVOL\<DOMAIN>\Policies\GP-Certs\`)
2. Open Group Policy Management Console (`gpmc.msc`) on the Domain Controller
3. Create a new GPO named `GlobalProtect Root CA Deployment` and link it to the OU containing target computers
4. Edit the GPO → Navigate to: **Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Trusted Root Certification Authorities**
5. Right-click **Trusted Root Certification Authorities** → Import → Browse to `GP-Root-CA.cer`
6. Complete the import wizard → Click Finish

The GPO applies to all computers in the linked OU on the next Group Policy refresh (every ~90 minutes, or force with `gpupdate /force`).

### 10.2 Deploy Machine Certificates to Endpoints

#### Method A — Manual Import (small deployments / testing)

1. Copy the `GP-Machine-HOSTNAME.p12` to the target endpoint via a secure channel
2. Open `certlm.msc` (Certificate Manager for Local Computer) — run as Administrator
3. Right-click **Personal > All Tasks > Import** → Browse to the .p12 file
4. Enter the passphrase (`<CERTIFICATE-PASSPHRASE>`) set during export
5. On the Certificate Store page, ensure "Place all certificates in the following store" is set to **Personal**
6. Click Finish — verify the machine certificate appears under Local Computer > Personal > Certificates
7. **Delete the .p12 file** from the endpoint and any transfer location after successful import

#### Method B — SCEP Auto-Enrollment (large deployments — recommended for >20 endpoints)

**Navigation:** Device > Certificate Management > SCEP > Add (on the firewall)

| Field | Value |
|---|---|
| SCEP Name | `GP-Machine-SCEP` |
| CA Certificate | `GP-Root-CA` |
| Subject | `CN=$host` (PAN-OS variable for hostname) |
| Key Size | 2048 |
| Digest | SHA-256 |
| SCEP URL | `https://<GATEWAY-PUBLIC-IP>/scep/GP-Machine-SCEP` (auto-generated) |
| Challenge | Set a challenge password — required by endpoints for enrollment |

Configure Windows endpoints to auto-enroll via the SCEP URL through GlobalProtect portal's certificate provisioning settings, or via Intune/SCCM SCEP profile pointing to the firewall's SCEP URL.

---

## 11. GlobalProtect Agent Installation on Endpoints

### 11.1 Download the Agent

Download from the Palo Alto Networks Customer Support Portal: https://support.paloaltonetworks.com

| OS | Package |
|---|---|
| Windows | `GlobalProtect-6.x.x.msi` (64-bit) |
| macOS | `GlobalProtect-6.x.x.pkg` |

### 11.2 Install the Agent

**Windows:** Run the MSI as Administrator, or deploy via Group Policy / SCCM / Intune.

**Silent Installation (GPO / SCCM deployment):**
```
msiexec /i GlobalProtect-6.x.x.msi PORTAL=vpn.example.com /qn /l*v C:\GP-Install.log
```

| Flag | Purpose |
|---|---|
| `PORTAL=` | Pre-populates the portal address in the agent |
| `/qn` | Silent install — no user interaction |
| `/l*v` | Verbose logging |

### 11.3 Configure the Portal Address in the Agent

If portal address was not pre-set during install: click the GlobalProtect icon in system tray → gear icon (Settings) → General → enter `vpn.example.com` in the Portal field → Apply.

---

## 12. Verification and Testing

### 12.1 Verify Certificates on the Endpoint

Open `certlm.msc` (Local Computer certificate store) as Administrator and verify:

| Store | Expected Certificate |
|---|---|
| Personal > Certificates | `GP-Machine-HOSTNAME` — Issued By: GlobalProtect Root CA |
| Trusted Root Certification Authorities > Certificates | `GP-Root-CA` — Issued To: GlobalProtect Root CA |

Double-click the machine certificate. Verify: "This certificate is OK", Subject matches machine FQDN, Issuer is GP-Root-CA, and it has not expired.

### 12.2 Verify Pre-Logon Tunnel Establishment

Reboot the endpoint. At the Windows logon screen (before entering credentials), GlobalProtect should establish the pre-logon tunnel.

**On the firewall, check active GP sessions:**
Navigate to: Network > GlobalProtect > Gateways > GP-GW-AlwaysOn > Monitor

Look for a session with `Username = pre-logon`.

**Via CLI:**
```
> show globalprotect-gateway current-user
```

Expected output includes a row with:
- `Username: pre-logon`
- `Domain: (machine name)`
- `Public IP: (endpoint's public IP)`
- `Virtual IP: (IP from your GP IP pool)`

### 12.3 Verify User Logon Tunnel Transition

Log in to Windows with domain credentials. The GlobalProtect agent transitions from pre-logon to user authentication. The system tray icon turns green and shows "Connected". Re-check gateway active sessions — Username should now show the user's login name instead of `pre-logon`.

### 12.4 Verify Always On Enforcement

Right-click the GlobalProtect system tray icon. Verify that "Disconnect" or "Sign Out" options are absent or grayed out.

Open Settings in the agent. Verify that the Portal Address field is read-only.

### 12.5 Verify Network Access Through the Tunnel

```
C:\> ping <INTERNAL-DNS-PRIMARY> -n 4
```

Check IP address:
```
C:\> ipconfig
```

Look for a virtual adapter labeled "PANGP Virtual Ethernet Adapter" with an IP in your GP IP pool range. All traffic should route through this adapter.

Verify on the firewall: Monitor > Logs > Traffic → filter by source zone VPN → confirm traffic from the endpoint's virtual IP is appearing.

---

## 13. Troubleshooting

### 13.1 Troubleshooting Reference Table

| Symptom | Likely Cause | Resolution |
|---|---|---|
| Agent shows "Connecting" indefinitely at pre-logon | Machine cert not found or not in Local Computer Personal store | Run `certlm.msc`, verify cert exists under Personal. Check cert chain resolves to GP-Root-CA in Trusted Roots. |
| SSL certificate error when connecting to portal | Root CA not trusted on endpoint / SAN missing on server cert | Deploy GP-Root-CA.cer via GPO to Trusted Roots. Verify server cert has IP and FQDN SANs. |
| Username shows "pre-logon" even after user logon | Agent config not transitioning to user auth; SSO not configured | Check App tab Connect Method = Pre-logon (Always On). Verify SSO is enabled. Check event logs for auth failures. |
| "Disconnect" option visible to user | Connect Method not set to Pre-logon (Always On) or Allow Sign Out still enabled | Re-check portal Agent Config App tab. Set Allow User to Sign Out = No. Commit and test. |
| Pre-logon tunnel connects but user cannot reach internal resources | Security policy missing for VPN zone to Trust zone | Add GP-VPN-to-Internal policy. Check route table for GP IP pool on the internal router. |
| Machine certificate rejected by gateway | Certificate Profile not assigned to gateway auth; wrong CA referenced | Verify gateway Client Authentication entry has Certificate Profile = GP-Machine-CertProfile. Confirm CA is GP-Root-CA. |
| Agent installed but shows "Not Connected" after reboot | PanGPS service not running; portal address not configured | Run `services.msc` and verify PanGPS is Started. Verify portal FQDN resolves via DNS on the endpoint. |
| Gateway IPsec tunnel fails; SSL fallback works but is slow | UDP/4501 blocked by ISP or intermediate firewall | Allow UDP/4501 inbound to gateway IP. Alternatively, configure portal to prefer SSL only. |

### 13.2 Key CLI Commands for Firewall Diagnostics

**GlobalProtect Gateway — Show Active Sessions:**
```
> show globalprotect-gateway current-user
```

**GlobalProtect Gateway — Show Statistics:**
```
> show globalprotect-gateway statistics
```

**GlobalProtect Portal — Show Active Sessions:**
```
> show globalprotect-portal current-user
```

**Test Certificate Validation:**
```
> test vpn ike-sa gateway GP-GW-AlwaysOn
```

**Show System Logs for GP Events:**
```
> show log system direction equal forward subtype equal globalprotect
```

### 13.3 Endpoint-Side Diagnostic Tools

**Windows — Collect GlobalProtect Logs:**
```
C:\Users\%USERNAME%\AppData\Local\Palo Alto Networks\GlobalProtect\PanGPA.log
```

**Windows — Force GP Agent Re-Connect:**
```
C:\> net stop pangps && net start pangps
```

**Windows — Verify Certificate Store from CLI:**
```
C:\> certutil -store My
C:\> certutil -store Root
```

**Windows — Check GP Virtual Adapter Route Table:**
```
C:\> route print
```
Look for `0.0.0.0/0` routed via the PANGP virtual adapter. If this route is missing, the full-tunnel is not active.

---

## 14. Ongoing Maintenance

### 14.1 Certificate Renewal Schedule

| Certificate | Lifetime | Action Required |
|---|---|---|
| Root CA (GP-Root-CA) | 10 years | Renew at year 9. Plan 6+ months in advance. All downstream certs must be re-issued when CA changes. |
| Server Certificate (GP-Server-Cert) | 2 years | Renew 60 days before expiry. Update SSL/TLS Service Profile after renewal. |
| Machine Certificates | 1 year | Automate renewal via SCEP. Manual renewal requires re-exporting a new .p12 to each endpoint. |

> **WARNING:** Expired machine certificates cause pre-logon tunnels to fail silently. Endpoints with expired machine certs show "Connecting..." at pre-logon and never connect. Implement monitoring for certificate expiry 90 days in advance.

### 14.2 Agent Version Updates
- Test new agent versions in a pilot group before broad deployment
- Portal can auto-distribute agent updates: Portal Agent Config > App tab > Upgrade — set to "Transparent" for silent upgrades
- Validate new agent version compatibility with your PAN-OS version before deployment

### 14.3 Monitoring and Alerting Recommendations
- Monitor active gateway session count daily — sudden drops indicate connectivity issues
- Alert on any commit that modifies GlobalProtect portal or gateway configuration
- Alert on certificate expiry: configure SNMP traps or syslog alerts for certificate objects within 90 days of expiry
- Regularly review Monitor > Logs > System filtered on `subtype = globalprotect` for authentication failures

---

## 15. Configuration Summary Checklist

| Item | Status |
|---|---|
| Root CA (GP-Root-CA) created on firewall | ☐ |
| Server Certificate (GP-Server-Cert) created and signed by GP-Root-CA | ☐ |
| Server Certificate includes IP and DNS SANs | ☐ |
| Machine Certificate created and signed by GP-Root-CA | ☐ |
| Certificate Profile (GP-Machine-CertProfile) created with GP-Root-CA | ☐ |
| SSL/TLS Service Profile (GP-SSL-Profile) created with GP-Server-Cert | ☐ |
| Tunnel Interface (tunnel.1) created and assigned to VPN zone | ☐ |
| VPN Security Zone created | ☐ |
| GlobalProtect Gateway created with Certificate Profile and IP Pool | ☐ |
| GlobalProtect Portal created with Certificate-based auth | ☐ |
| Portal Agent Config — Connect Method set to Pre-logon (Always On) | ☐ |
| Portal Agent Config — Allow User to Sign Out = No | ☐ |
| Portal Agent Config — Allow User to Disable App = No | ☐ |
| Security Policy: VPN → Trust (Allow internal access) | ☐ |
| Security Policy: VPN → Untrust (Allow internet via full-tunnel) | ☐ |
| NAT Policy: Source NAT for GP client internet traffic | ☐ |
| Firewall committed successfully | ☐ |
| Root CA deployed to endpoints via GPO (Trusted Root) | ☐ |
| Machine Certificate deployed to endpoint (Local Computer Personal) | ☐ |
| GlobalProtect agent installed on endpoint | ☐ |
| Pre-logon tunnel verified (username = pre-logon before user logon) | ☐ |
| User tunnel verified (username = domain user after logon) | ☐ |
| Always On enforcement verified (no disconnect option for user) | ☐ |
| Internal resource access verified through tunnel | ☐ |

---
*End of Article KB-GP-PRELOGON-001*
