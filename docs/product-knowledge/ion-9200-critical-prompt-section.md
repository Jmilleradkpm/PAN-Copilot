## CRITICAL PRODUCT KNOWLEDGE: PRISMA SD-WAN ION 9200 SERIES

Treat the following as authoritative product context for any question about **ION 9200**, **PAN-ION-9200**, Prisma SD-WAN data-center appliances, or high-capacity ION hardware. Do not confuse ION devices with PA-Series NGFWs: ION runs **Prisma SD-WAN** (Instant-On Network), managed by the Prisma SD-WAN controller (CloudBlades / Strata SD-WAN fabric), not PAN-OS security policy the way a PA-440 does.

### What it is
* **Prisma SD-WAN ION 9200** is a next-generation **software-defined WAN appliance** from Palo Alto Networks for **data center**, **large branch / campus**, and **remote office / enterprise edge** multi-gigabit roles.
* Official positioning: accelerate **SASE deployment into a data center** by providing high-performance WAN connectivity on an ION without bolting on extra hardware for rapid DC edge builds.
* **SKU / ordering name (common):** `PAN-ION-9200` (hardware appliance). Field-replaceable SSD SKU example: `PAN-ION-9200-SSD-480G`.
* Part of the **Prisma SD-WAN ION family** (Instant-On Network devices). Peer models for sizing context: smaller/mid platforms such as ION 3200 / 3200H / 5200; **9200 is the large multi-gigabit class** for DC / large campus / large branch.

### What it is for (use cases)
* **Data center SD-WAN edge** for Prisma SD-WAN / SASE (high throughput, dense fiber, dual PSUs).
* **Large campus or large branch** multi-WAN aggregation with app-aware path selection (Prisma SD-WAN policy sets / path quality), not classical PAN-OS App-ID policy.
* **SASE acceleration**: connect DC sites into the Prisma / SASE fabric quickly using controller-managed SD-WAN rather than only MPLS or pure IPsec hub designs.
* **PoE edge support**: power **external cellular gateways**, WLAN APs, IP phones, cameras via **PoE++** on multi-gig ports (designs that need LTE/5G failover or powered edge devices on the same box).
* **Smart SFP / higher-power SFP+** designs (optics and smart SFPs that need more power budget than older ION generations).
* **Bypass-aware inline WAN paths** on copper pairs for resilient deployments where fail-to-wire behavior on designated bypass pairs is required.

### What it is NOT
* Not a **PA-Series / VM-Series NGFW** running full PAN-OS security policy, content-ID, decryption, etc. as the primary identity.
* Not **Prisma Access** itself (Prisma Access is the cloud security service; ION is the **SD-WAN underlay/edge device** that can integrate toward SASE / Prisma Access designs).
* Not the older **CloudGenix** marketing name alone: product line is **Prisma SD-WAN**; hardware is still called **ION**.

### Hardware facts (from Palo Alto TechDocs: ION 9200 Hardware Reference)
| Attribute | Detail |
|-----------|--------|
| Role | Multi-gigabit device for remote office, data center, or enterprise large branch/campus |
| Memory | 64 GB |
| Storage | 480 GB internal + 480 GB external field-replaceable **NVMe SSD**; replace only powered down; use FSE guidance |
| Console | 1Ã— RJ-45 UART and Micro-USB Type-B console |
| USB | 1Ã— Type-A |
| Ethernet ports | Ports **1â€“22** are Ethernet; by default **DHCP-enabled**; **ports 1 and 2** used to reach the internet / controller path by default |
| Copper / MGig | **11Ã— 1G RJ45**; **4Ã— multi-gig 1G/2.5G/5G PoE++** (ports **9â€“12**, yellow bar between port numbers) |
| Fiber | **10Ã— 10G/1G SFP+** (ports **13â€“22**) |
| Bypass | Ports **1â€“8** are bypass ports (**4 pairs** of 1G RJ45) |
| PoE budget | **150 W** system total, **90 W max per PoE port** (802.3bt PoE++) |
| Power | **2Ã— 450 W** AC PSUs, **100â€“240 V**, 50â€“60 Hz; **hot-swappable redundant** FRU |
| Cooling | Forced air, **4 fans**, front (network ports) â†’ rear (PSUs) airflow |
| Form factor | Approx. **14.15" Ã— 17.15" Ã— 1.70"** (1U class), ~**15.5 lb**; **four-post rack** mount |
| Environment | Operating **0â€“40 Â°C** (to 3000 m); storage **âˆ’20â€“70 Â°C**; humidity operating 5â€“90% non-condensing |
| Certifications | IEC 62368-1, cTUVus, FCC & CE Class A, TEC, KCC |

### Throughput (datasheet-class figures; confirm against current Palo Alto datasheet for a given release)
Vendor / channel datasheets commonly quote class figures such as on the order of **~14â€“15 Gbps DC** and **~5â€“8 Gbps branch** (encrypted, packet-size dependent). Always state that **published throughput depends on packet size, encryption, and software version**, and point users to the current **Prisma SD-WAN ION device specifications** datasheet for firm RFQ numbers. Do not invent exact PPS or concurrent-session limits without a cited datasheet.

### Design and ops guidance you must apply
1. **Controller-first**: ION 9200 is claimed and managed via **Prisma SD-WAN** (site, circuit, device claiming, software image). Ask for controller tenant / site context when troubleshooting "offline ION" or claim failures.
2. **Port roles**: Distinguish **bypass pairs (1â€“8)**, **PoE multi-gig (9â€“12)**, and **SFP+ (13â€“22)**. Wrong cabling on bypass pairs vs routed WAN ports is a common field error.
3. **Internet / claim path**: Default guidance that **ports 1â€“2** are used for internet/DHCP toward controller; if claim fails, verify DHCP/DNS/HTTPS egress and which physical ports are actually uplinked.
4. **PoE planning**: Stay under **150 W system** and **90 W/port**; cellular gateways + multi-radio APs can oversubscribe PoE if not planned.
5. **HA / RPS**: Dual PSU for DC edge; treat PSU FRU as hot-swap capable; SSD replacement is **not** hot-plug (power down, certified FSE recommended).
6. **SASE integration**: When users mix **Prisma Access + Prisma SD-WAN**, separate underlay (ION circuits/paths) from Prisma Access security processing; do not tell them to "push a Panorama device group to the ION."
7. **Sizing vs siblings**: Prefer **ION 9200** for **DC / large campus multi-gig** edges; point **ION 5200 / 3200** families for smaller branch unless the user has 9200-class bandwidth or port density needs.
8. **Docs anchors** (cite when helpful):
   * https://docs.paloaltonetworks.com/hardware/ion-9200-hardware-reference
   * https://docs.paloaltonetworks.com/hardware/ion-9200-hardware-reference/ion-9200-overview
   * https://docs.paloaltonetworks.com/hardware/ion-9200-hardware-reference/ion-9200-overview/ion-9200-hardware-specifications
   * Prisma SD-WAN Instant-On Network device specifications datasheet (paloaltonetworks.com resources)

### Critical disambiguation (always enforce)
| User says | Correct product framing |
|-----------|-------------------------|
| "9200 firewall" / "PA-9200" | There is **no PA-9200 NGFW** in this context; they almost certainly mean **ION 9200** (SD-WAN) or a different PA chassis (e.g. PA- Panorama M-Series). Clarify. |
| "ION 9000" | Prior-generation large ION; **9200** is the current large multi-gig generation in this family line. |
| "CloudGenix 9200" | Legacy name; answer as **Prisma SD-WAN ION 9200**. |

\---
