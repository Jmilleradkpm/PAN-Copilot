# KB-SCM-AIOPS-0001 — AIOps & Strata Cloud Manager: Onboarding Telemetry, Configuration, Validation & Troubleshooting

**Article ID:** KB-SCM-AIOPS-0001  
**Applies To:** PAN-OS 10.2+, Panorama 10.2+, SCM, AIOps Free/Premium, Strata Logging Service / Cortex Data Lake  
**Audience:** Firewall engineers, Panorama administrators, SOC operations, network security teams, escalation engineers  
**Revision:** 1.0 — May 2026

---

> **CORE DIAGNOSTIC PRINCIPLE:** Strata Cloud Manager cannot analyze a device it cannot **identify, license, authenticate, reach, ingest from, and process**.
>
> Telemetry onboarding issues should be isolated in this order:
> 1. Tenant and CSP association
> 2. License and product activation
> 3. Device certificate
> 4. Telemetry enablement
> 5. Telemetry region alignment
> 6. DNS, NTP, proxy, service route, and security policy
> 7. Strata Logging Service / CDL connectivity
> 8. Panorama CloudConnector plugin (if Panorama is involved)
> 9. Cloud-side ingestion or processing delay

---

## Table of Contents

1. [Architecture & Data Flow](#1-architecture--data-flow)
2. [Prerequisites](#2-prerequisites)
3. [Enabling AIOps Telemetry (Step-by-Step)](#3-enabling-aiops-telemetry-step-by-step)
4. [Troubleshooting Methodology](#4-troubleshooting-methodology)
5. [Validating Telemetry Connectivity](#5-validating-telemetry-connectivity)
6. [Telemetry Data Sensitivity & Privacy](#6-telemetry-data-sensitivity--privacy)
7. [AIOps Features Available After Telemetry Activation](#7-aiops-features-available-after-telemetry-activation)
8. [Panorama M-700 Specific Considerations](#8-panorama-m-700-specific-considerations)
9. [Root Cause Matrix](#9-root-cause-matrix)
10. [Standard Remediation Workflow](#10-standard-remediation-workflow)
11. [Known Gotchas](#11-known-gotchas)
12. [Escalation Data to Collect](#12-escalation-data-to-collect)
13. [Prevention Checklist](#13-prevention-checklist)
14. [Final Diagnostic Rule](#14-final-diagnostic-rule)

---

## 1. Architecture & Data Flow

### 1.1 What Telemetry Is

Device telemetry is structured operational data collected from PAN-OS devices and Panorama and streamed to Palo Alto Networks cloud infrastructure. It improves visibility into device health, performance, capacity planning, and configuration posture. Telemetry is uploaded to **CDL (Cortex Data Lake)** for use by cloud applications including SCM and AIOps.

AIOps telemetry follows a **hub-and-spoke model**. Each managed device acts as a telemetry source and pushes structured data to CDL via an encrypted, certificate-authenticated TLS session. SCM subscribes to CDL as a consumer and surfaces aggregated, AI-processed results in the management plane.

### 1.2 Data Flow (Logical)

| Stage | Component | Transport |
|---|---|---|
| 1 — Collection | NGFW / Panorama (on-prem or cloud) | Local bundling |
| 2 — Transport | Management interface or service route | DNS / proxy / security policy |
| 3 — Ingestion | Cortex Data Lake (CDL) | TLS 443 to `logging.prod.datapath.prod.cdl.paloaltonetworks.com` |
| 4 — Processing | SCM / AIOps Engine | Internal Cortex bus (subscription) |
| 5 — Presentation | `stratacloudmanager.paloaltonetworks.com` | HTTPS (operator / admin access) |

> If any stage fails, Strata Cloud Manager may show **no data, stale data, delayed telemetry, or incomplete health/posture information.**

### 1.3 Telemetry Data Categories

| Category | Interval | Transport | Data Elements |
|---|---|---|---|
| System Health | 60 seconds | CDL Telemetry | CPU, memory, disk, fan, PSU, HA state, session table utilization |
| Configuration Snapshot | On change + 24 hr baseline | CDL Telemetry | Sanitized policy, object, zone, interface config (no credentials) |
| Traffic Telemetry | 5 minutes (aggregated) | CDL Logging | App-ID, User-ID, byte/session counts, threat summary |
| Device Analytics | 15 minutes | CDL Telemetry | BGP/OSPF adjacency, IPsec tunnel states, GlobalProtect gateway metrics |

### 1.4 AIOps Service Tiers

| Feature | AIOps Free / SCM Essentials | AIOps Premium / SCM Pro |
|---|---|---|
| Device Health Score | Yes | Yes |
| Best Practice Assessment | Read-only | Read-only + Remediation |
| Predictive Analytics | No | Yes |
| Capacity Forecasting | No | Yes |
| Custom Alerts & Thresholds | No | Yes |
| Software Upgrade Advisor | Basic | Full risk scoring |
| Tech Support File Analysis | No | Yes |
| Cortex Data Lake Retention | 30 days | Up to 1 year |

---

## 2. Prerequisites

### 2.1 Licensing & Entitlements

- Active Panorama or direct-to-SCM management license on each device
- Cortex Data Lake (CDL) tenant provisioned and associated with your Customer Support Portal (CSP) account
- AIOps Free is automatically included with any CDL entitlement. AIOps Premium requires a separate SKU: `PAN-AIOPS-NGFW-PREM`
- All devices must be registered to the **same CSP account/tenant** as the CDL instance

### 2.2 Software Versions

| Component | Minimum Version | Recommended |
|---|---|---|
| PAN-OS (Hardware NGFW) | 10.2.0 | 11.1.x (latest maintenance) |
| PAN-OS (VM-Series) | 10.2.0 | 11.1.x |
| Panorama | 10.2.0 | 11.1.x (must match or lead managed devices) |
| Cloud NGFW (AWS/Azure) | N/A | Supported natively via SCM |

> **Auto-Enablement:** Beginning with PAN-OS 10.2.17, 11.1.11, 11.2.8, 12.1.2 and later, telemetry is auto-enabled by default on new firewall/Panorama onboarding with settings centrally controlled through SCM. Auto-enabled means the configuration intent exists — it does **NOT** prove successful upload.

### 2.3 Network Connectivity Requirements

All connections are initiated **outbound** from the device. No inbound ports are required.

| FQDN / Endpoint | Port | Purpose |
|---|---|---|
| `*.paloaltonetworks.com` | TCP 443 | General SCM and support portal |
| `logging.prod.datapath.prod.cdl.paloaltonetworks.com` | TCP 443 | CDL telemetry ingest (primary) |
| `api.prod.datapath.prod.cdl.paloaltonetworks.com` | TCP 443 | CDL API (config snapshot push) |
| `stratacloudmanager.paloaltonetworks.com` | TCP 443 | SCM management plane |
| `identityserver.paloaltonetworks.com` | TCP 443 | OAuth 2.0 / JWT token issuance |
| `*.prod.di.paloaltonetworks.cloud` | TCP 443 | SCM data ingestion |
| `*.prod.reporting.paloaltonetworks.com` | TCP 443 | SCM reporting |
| `*.receiver.telemetry.paloaltonetworks.com` | TCP 443 | Telemetry receivers |
| `storage.googleapis.com` | TCP 443 | Google Cloud CDL backend |
| CDL logging service | TCP 444, 3978 | Strata Logging Service non-standard SSL ports |

> **SSL Inspection Warning:** If your perimeter firewall or proxy performs SSL/TLS inspection, you **MUST** add the CDL and SCM FQDNs above to your SSL inspection exemption list. Telemetry uses **certificate pinning** — inspecting and re-signing the TLS session will cause certificate validation failure on the device side.

---

## 3. Enabling AIOps Telemetry (Step-by-Step)

### Step 1 — Activate Cortex Data Lake

CDL must be activated from the Palo Alto Networks hub before devices can stream telemetry.

1. Log in to `hub.paloaltonetworks.com` with your CSP credentials.
2. Navigate to `Apps > Cortex Data Lake > Activate`.
3. Select your geographic **region for data residency** (US, EU, or APAC). This selection is **permanent** and affects where telemetry data is stored at rest.
4. Accept the terms and confirm activation. Provisioning takes approximately 5–10 minutes.
5. Note the **Tenant ID (Instance ID)** shown on the CDL overview page — required in the next steps.

### Step 2 — Link Panorama to CDL

This step establishes management-plane trust between Panorama and CDL.

1. In Panorama, navigate to `Panorama > Setup > Telemetry`.
2. Under **Cortex Data Lake**, click **Enable** and enter CSP credentials when prompted. Panorama performs an OAuth 2.0 device authorization grant.
3. After authentication, confirm the Tenant ID matches the CDL instance noted in Step 1.
4. Click `Commit > Commit to Panorama`. No device push is needed at this stage.

> **HA Pair:** If Panorama is in an HA pair, perform this procedure on the **active node only**. The passive node inherits CDL linkage through configuration synchronization after commit.

### Step 3 — Enable Device Telemetry on Managed Firewalls

**Via Panorama Template (Recommended):**

1. Navigate to `Device > Setup > Telemetry` within the Template scope.
2. Enable all telemetry categories: Application reports, Threat prevention reports, URL reports, File type identification, Health and performance monitoring, Passive DNS monitoring, Product usage statistics.
3. Set **Destination** to **Cortex Data Lake**.
4. Commit and Push the template to the relevant Device Groups.

**Per-Device (CLI):**

```bash
set deviceconfig system telemetry application-reports yes
set deviceconfig system telemetry threat-prevention-reports yes
set deviceconfig system telemetry url-reports yes
set deviceconfig system telemetry file-identification yes
set deviceconfig system telemetry health-performance-monitoring yes
set deviceconfig system telemetry passive-dns-monitoring yes
set deviceconfig system telemetry product-usage yes
commit
```

**Set Telemetry Region via CLI:**

```bash
configure
set deviceconfig system device-telemetry region <region>
commit
exit
```

### Step 4 — Enroll Devices in SCM

1. Log in to `stratacloudmanager.paloaltonetworks.com`.
2. Navigate to `Workflows > Onboarding > Add Devices`.
3. Choose onboarding method:
   - **Panorama-managed (recommended):** selects Device Groups to import
   - **Direct:** enters serial number and generates activation code
4. Verify the inventory is complete. Assign **Site** tags for grouping in AIOps dashboards.
5. Click **Finish**. Initial AIOps data population takes **2–6 hours** as SCM ingests the telemetry backlog from CDL.

---

## 4. Troubleshooting Methodology

### Step 1: Confirm Tenant and CSP Association

A device must be associated with the correct CSP account, tenant, and SCM/AIOps application.

**Check:** In SCM, go to `System Settings > Device Management > Device Associations` or `Cloud Managed Devices`. Confirm the firewall or Panorama serial number is present and associated with the correct licensed product.

**Failure Indicators:**
- Device registered in CSP but not visible in the tenant
- Device appears under a different tenant
- Device associated with Strata Logging Service but not with SCM/AIOps
- Firewall serial number incorrect or duplicated

**Fix:** Re-associate the device to the correct tenant. Confirm the correct CSP account and SCM tenant are selected in the UI.

---

### Step 2: Confirm License State

```bash
request license info
```

| Problem | Result |
|---|---|
| Expired support license | Device may fail cloud authentication or license validation |
| Wrong CSP account | Device appears in the wrong tenant or cannot be associated |
| Missing Strata Logging Service license | Telemetry may not upload as expected |
| License assigned to different serial | Device appears eligible but does not activate correctly |
| Region mismatch between license and telemetry destination | Commit or upload failures may occur |

---

### Step 3: Validate Device Certificate

The device certificate is a **core trust requirement**. Without it, the firewall cannot authenticate to Palo Alto Networks cloud services.

```bash
show device-certificate status
```

**Expected Result:** Installed, Valid, Not expired, Not revoked, Associated with correct device identity

**Fix:**
1. Configure DNS and NTP
2. Confirm the device can reach Palo Alto certificate and OCSP/CRL services
3. Reinstall or renew the device certificate
4. Commit changes and re-test telemetry

---

### Step 4: Confirm Telemetry Is Enabled

```bash
show device-telemetry details
show device-telemetry settings
```

Navigate to `Device > Setup > Telemetry` in the GUI to verify telemetry is enabled, destination region is configured, and commit has completed. Trigger manual collection if needed:

```bash
request device-telemetry collect-now
show device-telemetry collect-now
```

---

### Step 5: Validate Telemetry Region Alignment

Region mismatch is one of the most common causes of onboarding telemetry confusion. If an organization has a Strata Logging Service license, telemetry data can **only** be sent to the same region where the SLS instance resides.

```bash
show device-telemetry settings
request plugins cloud_services logging-service status
```

| Component | Requirement |
|---|---|
| Device telemetry region | Must match SLS/CDL region when SLS/CDL is licensed |
| Strata Logging Service tenant | Must be in the expected tenant service group |
| SCM app region | Must support or process the selected region |
| Tenant data residency | Must align with organizational data governance requirements |

---

### Step 6: Validate DNS and NTP

DNS is required to resolve Palo Alto cloud FQDNs. NTP is required because certificates, TLS sessions, and cloud authentication depend on accurate device time. **Clock skew greater than 300 seconds causes CDL JWT authentication failures.**

```bash
show clock
show ntp
ping host <telemetry-FQDN>
show device-telemetry details
```

**Fix:**
- Configure DNS servers under `Device > Setup > Services`
- Configure NTP servers. Expected output: `synced: yes`, `stratum: 2–4`, `reachability: 377`
- Confirm management interface or service route can reach DNS and NTP
- Re-test telemetry FQDN resolution and trigger collection again

---

### Step 7: Validate FQDNs, Ports, App-IDs, and Proxy

| Category | Validate |
|---|---|
| DNS | Firewall/Panorama can resolve telemetry receiver FQDN |
| TLS | TCP 443 allowed |
| Logging service | TCP 444 and 3978 allowed where required |
| Google services | Required Google base connectivity allowed (`storage.googleapis.com`) |
| OCSP/CRL | Certificate revocation checks allowed |
| Proxy | Allows Palo Alto cloud FQDNs and non-standard SSL ports |
| Upstream firewall | Does not decrypt, block, or misclassify telemetry traffic |
| Security policy | Allows telemetry from management or service-route source IP |

> **Security Policy:** If a Palo Alto firewall is securing the outbound path from Panorama or another firewall to Strata Logging Service, write policy using the correct App-IDs (`paloalto-device-telemetry`, `google-base`) and service ports. Do **not** assume generic `ssl` and `web-browsing` are sufficient.

---

### Step 8: Validate Service Routes

By default, telemetry may use the management interface. In restricted environments, the management interface often has no internet access.

Navigate to `Device > Setup > Services > Service Route Configuration`.

> **Common Failure:** The firewall can reach the internet from a dataplane interface, but telemetry is sourced from the management interface, which has no route or is blocked by the upstream firewall.

**Fix:**
1. Configure custom service route for Palo Alto Networks services or telemetry
2. Select correct source interface and source address
3. Confirm routing table has a default route or specific route to the internet
4. Commit and test DNS and telemetry upload again

---

### Step 9: Check Telemetry Collection and Upload Status

```bash
show device-telemetry details
show device-telemetry stats all
show device-telemetry collect-now
request device-telemetry collect-now
tail follow yes mp-log device_telemetry.log
tail follow yes mp-log device_telemetry_curl.log
```

| Log Indicator | Meaning | Likely Fix |
|---|---|---|
| `DNS lookup failed` | Device cannot resolve telemetry endpoint | Fix DNS, service route, proxy DNS handling |
| `Client Certificate issue` | Certificate missing, expired, or invalid | Reinstall/renew device certificate |
| `Send File to CDL Receiver Failed` | Bundle created but upload failed | Check SLS region, ports, FQDNs, proxy, upstream firewall |
| Last attempt updates, last success does not | Device is trying but cloud upload fails | Check network path and logs |
| Neither timestamp updates | Collection process may not be running or config not committed | Commit, then verify process is running |
| Upload success but SCM still stale | Processing delay or tenant/region mismatch | Wait expected interval, verify tenant, open TAC case |

---

### Step 10: Panorama-Specific Checks

For Panorama visibility into SCM, the **Panorama CloudConnector plugin** is required. Prerequisites: device certificate installed, CloudConnector plugin installed, Panorama running PAN-OS **10.2.3 or later**, and device telemetry enabled on Panorama.

```bash
show plugins installed
show device-certificate status
show device-telemetry details
show device-telemetry settings
```

**Enable CloudConnector Plugin:**

```bash
request plugins cloudconnector enable basic
```

> **Important:** CloudConnector is preinstalled with newer Panorama versions. If both the old AIOps plugin and CloudConnector plugin are installed, **remove the older AIOps plugin** and keep the latest CloudConnector plugin.

> **Expected Delay:** After installing the Panorama CloudConnector plugin and enabling Device Telemetry, wait **up to 24 hours** before data appears in SCM Dashboards and Activity Insights.

---

### Step 11: Validate Cloud Management Connection (SCM-Managed Firewalls)

```bash
show cloud-management-status
```

Verify that the firewall successfully connected to an SCM endpoint (`connected status displays Yes`). Check `System Settings > Device Management > Cloud Managed Devices` and confirm: serial number, device model, IP address, onboarding status (successful), and configuration push status.

> **After successful onboarding**, two configuration pushes occur by default: one to enable Advanced Routing Engine (restarts firewall), and a second to push configuration from SCM.

---

## 5. Validating Telemetry Connectivity

### 5.1 On-Device CLI Verification

| Command | Expected Output / What to Check |
|---|---|
| `show system telemetry statistics` | All categories show `Sent > 0`; `Failed = 0`; `Connection State = Connected` |
| `show logging-status` | CDL forwarding shows `Connected` and non-zero Sent count |
| `show system info \| match telemetry` | `telemetry-enabled: yes` |
| `debug log-collector log-collection-stats show` | CDL connection shows `UP` (useful on Panorama log collector) |
| `test panorama connectivity` | (Panorama only) All entries show `Success` |
| `show device-telemetry stats all` | DNS, certificate, send failure counts; last success timestamp |
| `show ntp` | `synced: yes`, `stratum: 2–4`, `reachability: 377` |

### 5.2 CDL Connectivity Test

To test network-level SSL connectivity to the CDL logging endpoint from the device management plane:

```bash
test connection protocol ssl host logging.prod.datapath.prod.cdl.paloaltonetworks.com port 443
```

A successful result returns `SSL handshake OK` and the server certificate chain. A failure indicates a firewall rule block or SSL inspection interference.

> **Note:** CDL telemetry traffic originates from the **management plane interface (MGT port)**, not the dataplane. Ensure your management access policy permits outbound TCP/443 from the MGT interface IP. If using in-band management, confirm the routing and security policy allow this traffic on the correct zone.

### 5.3 SCM Portal Validation

- Navigate to `Insights > Device Health`. Confirm enrolled devices appear with a Health Score.
- Navigate to `AIOps > Best Practice Assessment`. Devices with active telemetry show a populated BPA report. Devices showing **'Awaiting Data'** have not yet delivered enough telemetry — wait up to 6 hours.
- Check the **Last Seen** timestamp in `Manage > Inventory`. Should be within the last 5 minutes for healthy telemetry.

---

## 6. Telemetry Data Sensitivity & Privacy

### 6.1 What Is NOT Transmitted

- Firewall administrator credentials or API keys
- User passwords or authentication tokens
- Full packet payloads or application content
- Personally identifiable information (PII) extracted from traffic
- Pre-shared keys (PSK) for IPsec or other VPN tunnels
- SSL/TLS private keys or certificates with private key material

### 6.2 What IS Transmitted

- Device serial numbers, model numbers, PAN-OS versions, and hostnames
- **Sanitized** policy rule names and object names (no IP addresses in config snapshots)
- Aggregate traffic statistics (top apps, threat counts, session totals) — not per-flow records
- Interface and routing table states
- Hardware sensor readings (temperature, fan speed, PSU status)
- HA cluster membership and failover event history

> **Compliance Note:** For organizations subject to GDPR, HIPAA, or FedRAMP controls, review Palo Alto Networks' Data Processing Addendum (DPA). CDL data residency can be scoped to EU regions to satisfy GDPR locality requirements. AIOps telemetry is **NOT FedRAMP authorized** at this time.

> Automatically created users such as `_cliuser` or `__telemetryuser` may appear while telemetry is enabled. These are normal and used for internal telemetry collection operations.

---

## 7. AIOps Features Available After Telemetry Activation

### 7.1 Device Health Scoring

SCM aggregates health telemetry into a composite **Device Health Score (0–100)** for each firewall. Scores below 70 trigger automated recommendations. Contributing factors:

- Hardware sensor health (PSU, fan, temperature)
- HA state and last failover recency
- Dataplane and management plane CPU sustained utilization
- Session table headroom
- Security content (Content, AV, WildFire) update currency

### 7.2 Best Practice Assessment (BPA)

BPA compares device configuration against Palo Alto Networks security best practices across **six domains**: Security Profiles, Decryption, WildFire, Zones, Authentication, and Logging. Each check is rated **Pass, Fail, or Warning** with a remediation recommendation attached to each failure.

BPA data refreshes every **24 hours** based on configuration snapshot telemetry. A manual refresh can be triggered via `Insights > Best Practice Assessment > Refresh`.

### 7.3 Software Upgrade Advisor (AIOps Premium)

Using telemetry from your specific hardware platform, in-use features, and content versions, the Software Upgrade Advisor produces a **risk score** for upgrading to any target PAN-OS release. It cross-references known issues in that release against your active feature set and flags potential compatibility risks before the upgrade is executed.

### 7.4 Predictive Failure Detection (AIOps Premium)

Machine learning models trained on anonymized telemetry from the broader Palo Alto Networks customer base identify **leading indicators of hardware and software failures up to 7 days in advance**. Alerts surface in SCM's notification center and can be forwarded to external systems via webhook integration.

---

## 8. Panorama M-700 Specific Considerations

The Panorama M-700 appliance in dedicated Log Collector / Collector Group mode requires additional steps for CDL telemetry.

- Each M-700 Log Collector must be **individually linked to CDL** via `Panorama > Collector Groups > [Group] > Log Forwarding`. Add the CDL forwarding destination to each Collector Group profile.
- Verify the M-700 MGT port has outbound access to the CDL logging endpoint. M-700 log collector interfaces are on a **separate routing table** from the Panorama management plane.
- Use `debug log-collector log-collection-stats show` on the M-700 CLI to confirm CDL forwarding is active and no backpressure is accumulating.
- For M-700 in **HA pairs**, CDL forwarding state is **not synchronized** between nodes. Both nodes independently maintain CDL sessions — confirm both show `Connected`.

---

## 9. Root Cause Matrix

| Root Cause | Evidence | Resolution |
|---|---|---|
| Device not associated to correct tenant | Device missing from SCM or appears under wrong tenant | Re-associate serial to correct CSP/tenant |
| Missing license | `request license info` does not show expected entitlement | Activate or assign correct SCM/AIOps/SLS license |
| Expired/missing device certificate | `show device-certificate status` fails | Install or renew device certificate |
| Telemetry disabled | `show device-telemetry settings` shows disabled | Enable telemetry and commit |
| Wrong telemetry region | Region differs from SLS/CDL region | Set telemetry region to match SLS/CDL |
| DNS failure | `DNS lookup failed` in telemetry stats | Fix DNS and service route |
| NTP/time issue | Certificate errors or clock skew >300s | Configure NTP and verify clock |
| Proxy blocking traffic | Direct path fails; proxy logs deny traffic | Allow required FQDNs and ports |
| Upstream firewall blocking App-ID | Traffic denied by security policy | Allow required App-IDs (`paloalto-device-telemetry`, `google-base`) and ports |
| Wrong service route | Telemetry sourced from blocked interface | Configure service route |
| Panorama plugin missing | `show plugins installed` missing CloudConnector | Install/enable CloudConnector plugin |
| Old AIOps plugin conflict | Both AIOps and CloudConnector plugins installed | Remove old AIOps plugin, keep latest CloudConnector |
| SSL inspection breaking telemetry | Certificate validation failure on device side | Add CDL/SCM FQDNs to SSL inspection exemption list |
| Normal ingestion delay | Recent onboarding, no failure logs | Wait expected processing interval (up to 6–24 hours) |
| Cloud-side issue | Device uploads successfully, SCM still stale | Open TAC case with telemetry logs and timestamps |

---

## 10. Standard Remediation Workflow

### 10.1 Step-by-Step Remediation

**1. Confirm Device Identity**
```bash
show system info
request license info
```
Verify: serial number, model, PAN-OS version, CSP account, tenant, SCM/AIOps product association, SLS/CDL region.

**2. Confirm Certificate**
```bash
show device-certificate status
```
Fix certificate issues **before continuing**. Telemetry troubleshooting is unreliable if the firewall cannot authenticate to Palo Alto cloud services.

**3. Confirm Telemetry Settings**
```bash
show device-telemetry settings
show device-telemetry details
```
Verify: enabled, correct region, endpoint present, no obvious configuration error.

**4. Confirm Network Path**
```bash
ping host <telemetry-endpoint-FQDN>
```
Verify: DNS server reachability, default route or service route, proxy path, upstream firewall logs, security policy match, SSL decryption exclusions if applicable.

**5. Trigger Collection**
```bash
request device-telemetry collect-now
show device-telemetry collect-now
tail follow yes mp-log device_telemetry.log
tail follow yes mp-log device_telemetry_curl.log
```

**6. Check Statistics**
```bash
show device-telemetry stats all
```
- `DNS failure` → fix DNS/service route
- `Certificate issue` → fix device certificate, time, or OCSP
- `Send failure` → fix ports, FQDNs, proxy, or region
- `No collection attempt` → confirm telemetry config and commit

**7. Validate in SCM**
- Check Command Center, Dashboards, Activity Insights
- Check `System Settings > Device Management`
- Check `Configuration > Operations > Push Status`
- For Panorama visibility deployments, allow **up to 24 hours** after enabling telemetry and installing the plugin before assuming ingestion has failed.

### 10.2 Re-linking CDL After Certificate Expiry

If the CDL authorization token expires (typically after 1 year) or the CSP password changes:

1. In `Panorama > Setup > Telemetry`, click **Unlink Cortex Data Lake**
2. Re-authenticate using updated CSP credentials
3. Commit. Devices do not need an individual commit — the link is managed at the Panorama level.

---

## 11. Known Gotchas

### 11.1 Auto-Enabled Does Not Mean Successfully Uploading

PAN-OS can auto-enable telemetry in newer releases, but upload still fails if the device cannot reach the telemetry receiver, the certificate is invalid, the region is wrong, or the tenant association is incorrect.

### 11.2 Region Mismatch Can Create Partial Visibility

A firewall may collect telemetry locally but fail to upload or experience delayed processing if the telemetry destination, SLS region, and SCM processing region are misaligned.

### 11.3 Panorama Requires Plugin AND Telemetry

Installing only the CloudConnector plugin is insufficient. Panorama also needs **device telemetry enabled**, a **valid certificate**, and **outbound access** to the correct cloud services.

### 11.4 Management Interface Is Often the Wrong Path

In secure environments, management networks frequently have no direct internet egress. If telemetry uses the management interface by default, the fix may be a **service route** rather than a telemetry setting change.

### 11.5 Proxy Rules Must Include Non-Standard Ports

A proxy allowing only TCP 443 may still break SLS or telemetry-related communication because Palo Alto Networks documents **non-standard SSL ports 3978 and 444** for logging service connectivity.

### 11.6 BPA Stale Data

If Best Practice Assessment shows data older than 48 hours, the configuration snapshot push may be failing. Check `api.prod.datapath` CDL endpoint access and commit a minor change to force a new snapshot.

---

## 12. Escalation Data to Collect

**On every affected firewall/Panorama:**

```bash
show system info
request license info
show device-certificate status
show device-telemetry settings
show device-telemetry details
show device-telemetry stats all
show device-telemetry collect-now
show clock
show ntp
show jobs all
```

**For Panorama:**
```bash
show plugins installed
request plugins cloud_services logging-service status
debug log-collector log-collection-stats show
tail follow yes mp-log logrcvr.log
```

**For SCM-Managed Firewalls:**
```bash
show cloud-management-status
```

**Log Files:**
```bash
tail lines 200 mp-log device_telemetry.log
tail lines 200 mp-log device_telemetry_curl.log
tail follow yes mp-log ms.log
tail follow yes mp-log agent.log
grep pattern 'CDL|telemetry|cortex' mp-log ms.log
```

**Information to Provide to TAC:**
- Firewall or Panorama serial number
- Tenant name / TSG and CSP account
- Strata Logging Service region and telemetry destination region
- SCM region and PAN-OS version
- Panorama version and CloudConnector plugin version
- Time of last successful telemetry upload and last failed upload
- Screenshots of SCM device status
- Upstream firewall/proxy deny logs
- Whether SSL decryption is applied to Palo Alto cloud traffic

---

## 13. Prevention Checklist

Use this checklist for every new AIOps / Strata Cloud Manager onboarding:

| Control | Required State |
|---|---|
| CSP account | Correct account selected |
| Tenant | Correct tenant / TSG selected |
| License | SCM/AIOps/SLS entitlement active |
| Serial number | Correct firewall or Panorama serial associated |
| PAN-OS | Supported version (10.2.0 minimum) |
| Device certificate | Installed and valid |
| DNS | Configured and tested |
| NTP | Configured, accurate, skew <300s |
| Telemetry | Enabled (all recommended categories) |
| Telemetry region | Matches SLS/CDL region where required |
| Service route | Correct source interface and source IP |
| Proxy | Allows required FQDNs and ports (including TCP 444, 3978) |
| SSL Inspection | CDL/SCM FQDNs exempt from inspection |
| Upstream firewall | Allows required App-IDs and ports |
| Panorama plugin | CloudConnector installed and enabled (old AIOps plugin removed) |
| Commit | Successful |
| SCM validation | Device appears in correct view with Health Score |
| Ingestion wait | Allow 2–6 hours for initial population; 24 hours for Panorama-connected |

---

## 14. Final Diagnostic Rule

```
Device Identity → License → Certificate → Telemetry Config → Region →
DNS/NTP → Service Route → Proxy/Security Policy → SSL Inspection →
CDL Upload → SCM Processing
```

Do **not** start by assuming a cloud-side problem. The highest-probability causes are usually **local or path-based**: wrong tenant, missing certificate, wrong telemetry region, blocked FQDN/port, bad DNS, bad service route, SSL inspection interference, or Panorama plugin mismatch.

### CLI Quick Reference

| Command | Purpose |
|---|---|
| `show system telemetry statistics` | Overall telemetry status and counters |
| `show logging-status` | CDL log forwarding state |
| `show system info \| match telemetry` | Quick telemetry-enabled check |
| `show device-telemetry details` | Detailed telemetry configuration and status |
| `show device-telemetry stats all` | DNS, certificate, send failure counts |
| `show device-telemetry settings` | Telemetry categories and region |
| `show device-certificate status` | Device certificate validity |
| `show ntp` | NTP synchronization status |
| `show cloud-management-status` | SCM cloud management connectivity |
| `show plugins installed` | Installed Panorama plugins |
| `request license fetch` | Refresh license entitlements from CSP |
| `request device-telemetry collect-now` | Trigger manual telemetry collection |
| `test connection protocol ssl host <cdl-fqdn> port 443` | Network-level SSL connectivity test to CDL |
| `debug log-collector log-collection-stats show` | CDL forwarding state on Panorama/M-700 |

---

*End of Article KB-SCM-AIOPS-0001*
