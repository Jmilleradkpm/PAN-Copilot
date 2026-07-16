# Prisma SD-WAN ION 9200 — Product Guide (Critical Reference)

**KB ID:** KB-SDWAN-ION9200-001  
**Product:** Palo Alto Networks Prisma SD-WAN Instant-On Network (ION) 9200  
**Audience:** Field engineers, architects, and admins sizing or deploying large-branch / data-center SD-WAN edges  
**Primary docs:** [ION 9200 Hardware Reference](https://docs.paloaltonetworks.com/hardware/ion-9200-hardware-reference)

---

## 1. What the ION 9200 is

The **Prisma SD-WAN ION 9200** is a **next-generation software-defined WAN appliance** for:

- **Data center** SD-WAN / SASE edges  
- **Enterprise large branch or campus** multi-gigabit sites  
- **Remote office** deployments that need dense fiber, multi-gig copper, PoE, and dual power  

Palo Alto positions it to **accelerate SASE deployment into a data center** by providing high-performance WAN connectivity on an ION without requiring extra hardware just to stand up DC WAN connectivity.

**Common orderable hardware name:** `PAN-ION-9200`  
**Field-replaceable SSD (example):** `PAN-ION-9200-SSD-480G`

It is part of the **Prisma SD-WAN ION** family (Instant-On Network devices). It is **not** a PA-Series NGFW running PAN-OS security policy as its primary OS identity.

---

## 2. What it is for (use cases)

| Use case | Why ION 9200 fits |
|----------|-------------------|
| DC SD-WAN edge for Prisma SD-WAN / SASE | Multi-gig class performance, dual PSUs, dense SFP+ |
| Large campus / large branch aggregation | Many Ethernet ports, multi-gig PoE, fiber uplinks |
| Cellular / powered edge designs | PoE++ multi-gig ports for cellular gateways, APs, phones, cameras |
| Smart SFP / high-power optics | Higher-power SFP+ budget vs older ION generations |
| Fail-to-wire style copper paths | Dedicated **bypass pairs** on ports 1–8 |

Typical control plane: **Prisma SD-WAN controller** (claim device, assign site/circuits, policy sets, path quality, software image). Integration with **Prisma Access** is a **SASE design** topic (underlay vs cloud security service), not “push a Panorama device group to the ION.”

---

## 3. What it is not

- **Not** a **PA-9200** NGFW (that product name is a common mix-up; clarify).  
- **Not** Prisma Access itself (cloud security service).  
- **Not** managed primarily like a PAN-OS firewall via Panorama device groups for day-2 security policy.  
- Legacy marketing may say **CloudGenix**; current name is **Prisma SD-WAN**, hardware still **ION**.

---

## 4. Hardware specifications (TechDocs)

Source: Palo Alto Networks *ION 9200 Hardware Specifications* (Hardware Reference).

| Feature | ION 9200 |
|---------|----------|
| Description | Multi-gigabit device for remote office, data center, or enterprise large branch/campus |
| Console | 1× RJ-45 UART / Micro-USB Type-B console |
| WAN/LAN | Ports **1–22** Ethernet; default **DHCP-enabled**; **ports 1 and 2** used to connect to the internet by default |
| Copper | **11× 1G RJ45** |
| Multi-gig PoE | **4× 1G/2.5G/5G PoE++** (ports **9–12**, yellow bar between numbers) |
| Fiber | **10× 10G/1G SFP+** (ports **13–22**) |
| Bypass | Ports **1–8** bypass (**4 pairs**), 1G RJ45 |
| USB | 1× Type-A |
| PoE budget | **150 W** per system, **90 W** max per port |
| Memory | **64 GB** |
| Flash / SSD | **480 GB** internal, **480 GB** external field-replaceable **NVMe** SSD |
| Power | **2× 450 W** AC, 100–240 V, 50–60 Hz; **redundant, hot-swappable** |
| Cooling | Forced air, **4 fans**; front (ports) → rear (PSUs) |
| Dimensions | ~14.15" × 17.15" × 1.70" |
| Weight | ~15.5 lb |
| Mount | Four-post rack |
| Operating temp | 32–104 °F (0–40 °C) at up to 3000 m |
| Storage temp | −4–158 °F (−20–70 °C) |
| Humidity | Operating 5–90% non-condensing; storage 5–95% |
| Certifications | IEC 62368-1, cTUVus, FCC & CE Class A, TEC, KCC |

### Front-panel mental model

1. **Ports 1–8** — bypass pairs (1G RJ45)  
2. **Ports 9–12** — multi-gig **PoE++**  
3. **Ports 13–22** — **SFP+** 10G/1G  
4. Console RJ-45 + Micro-USB, USB-A, LEDs, power, SSD tray  

(See TechDocs front-panel table for exact silk-screen mapping.)

---

## 5. Throughput (class figures only)

Channel / datasheet materials often quote **class** numbers such as roughly **14–15 Gbps data-center** and **5–8 Gbps branch** (encrypted, packet-size dependent).  

**Always:**

- Call out packet size / encryption / software version sensitivity  
- Prefer the current **Prisma SD-WAN Instant-On Network device specifications** datasheet for RFQ or design guarantees  
- Do not invent session counts or PPS without a cited source  

---

## 6. Sizing vs other ION models

| Class (family) | Typical role |
|----------------|--------------|
| ION 3200 / 3200H | Smaller branch / hardened variants |
| ION 5200 | Medium branch / mid capacity |
| **ION 9200** | **Multi-gig large branch, campus, data center** |

If the user only needs a small site with limited WAN bandwidth, do not default to 9200 solely because it is “newest.”

---

## 7. Deployment checklist (field)

1. **Rack** four-post; verify front-to-rear airflow.  
2. **Dual PSU** on separate feeds for DC edge.  
3. **Claim path:** uplink on default internet ports (commonly **1–2**), DHCP/DNS/HTTPS to controller.  
4. **Circuits:** map ISP/MPLS/LTE to correct physical ports; document bypass pair usage.  
5. **PoE math:** total ≤ **150 W**, per-port ≤ **90 W**.  
6. **Optics:** match SFP+/1G SFP to distance and DDM; respect smart-SFP power needs.  
7. **Controller:** site, device claim, image version, policy set / path quality, circuit labels.  
8. **SASE:** if Prisma Access is in scope, separate underlay (ION paths) from cloud security nodes.  
9. **SSD replace:** power down fully; use `PAN-ION-9200-SSD-480G`; certified FSE recommended.  

---

## 8. Troubleshooting starters

| Symptom | First checks |
|---------|----------------|
| Device offline / unclaimed | Physical link on claim ports, DHCP, DNS, outbound HTTPS to controller, firewall on path, wrong port used for internet |
| No PoE device power | Port is 9–12?, budget 150 W system / 90 W port, cable category, device class |
| Fiber down | SFP type 1G vs 10G, polarity, DOM, admin state in controller |
| Unexpected fail-open/closed behavior | Confirm traffic is on **bypass pairs 1–8** vs normal routed ports |
| Performance short of datasheet | Packet size, encryption, path policy, single vs multi-circuit, software version |

---

## 9. Critical disambiguation

| User phrase | Correct framing |
|-------------|-----------------|
| “PA-9200” / “9200 firewall” | Likely **ION 9200** SD-WAN; there is no standard **PA-9200** NGFW. Clarify model. |
| “ION 9000” | Prior large generation; **9200** is current multi-gig large class in this line. |
| “CloudGenix 9200” | Answer as **Prisma SD-WAN ION 9200**. |

---

## 10. References

- [ION 9200 Overview](https://docs.paloaltonetworks.com/hardware/ion-9200-hardware-reference/ion-9200-overview)  
- [ION 9200 Hardware Specifications](https://docs.paloaltonetworks.com/hardware/ion-9200-hardware-reference/ion-9200-overview/ion-9200-hardware-specifications)  
- [ION 9200 Front Panel](https://docs.paloaltonetworks.com/hardware/ion-9200-hardware-reference/ion-9200-overview/ion-9200-front-panel)  
- [ION 9200 Hardware Reference (root)](https://docs.paloaltonetworks.com/hardware/ion-9200-hardware-reference)  
- Prisma SD-WAN Instant-On Network device specifications (paloaltonetworks.com datasheet resources)  

---

*ADKCyber internal KB for PAN Copilot. Keep aligned with official TechDocs when Palo Alto revises the hardware reference.*
