#!/usr/bin/env python3
"""
Seed the known-issues database with real Palo Alto Networks addressed issues.

Rows were pulled from the official PAN-OS release notes (addressed-issues pages)
on docs.paloaltonetworks.com and condensed into ADKCyber's own wording. Issue IDs
and source URLs are preserved so PAN Copilot can point users at the authoritative
page. This is a representative seed across current trains, not the full corpus.
Run release_notes_ingest.py for the complete history.

Usage: python seed_known_issues.py
"""

from known_issues_db import KnownIssuesDB, DB_PATH

S_1113 = "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-release-notes/pan-os-11-1-13-known-and-addressed-issues/pan-os-11-1-13-addressed-issues"
S_1121 = "https://docs.paloaltonetworks.com/pan-os/11-2/pan-os-release-notes/pan-os-11-2-11-known-and-addressed-issues/pan-os-11-2-11-addressed-issues"
S_1021 = "https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-release-notes/pan-os-10-2-16-known-and-addressed-issues/pan-os-10-2-16-addressed-issues"
S_1217 = "https://docs.paloaltonetworks.com/ngfw/release-notes/12-1/pan-os-12-1-7-known-and-addressed-issues/pan-os-12-1-7-addressed-issues"
S_CVE = "https://security.paloaltonetworks.com/"

SEED = [
    # PAN-OS 11.1.13
    ("PAN-306534", "11.1.13", "all_task process repeatedly restarts from memory pool corruption while processing fragmented DNS over HTTPS (DoH) JSON queries.", "DNS Security", S_1113),
    ("PAN-306502", "11.1.13", "TLS connection fails on TLS 1.2 or below when header insertion plus send-TLS-handshake-to-CTD is enabled and traffic hits a no-decrypt rule.", "Decryption", S_1113),
    ("PAN-306306", "11.1.13", "Panorama in FIPS-CC mode has inter-device TLS failures with RSA and RSA-PSS signature algorithms across multiple L7 services.", "Panorama", S_1113),
    ("PAN-305480", "11.1.13", "pan_task process stops responding while processing DoH JSON traffic with DoH Security enabled, taking the dataplane down.", "DNS Security", S_1113),
    ("PAN-304496", "11.1.13", "After re-registering a different IP tag for the same IP via XML API, dynamic address group membership is not updated on the dataplane, causing incorrect security policy enforcement.", "User-ID", S_1113),
    ("PAN-304229", "11.1.13", "Panorama web interface cannot disable Lifesize under the IPSec Crypto profile.", "Panorama", S_1113),
    ("PAN-303379", "11.1.13", "show system resources CLI displays incorrect CPU usage values that do not add up to 100 percent.", "CLI", S_1113),
    ("PAN-303051", "11.1.13", "Panorama reportd memory leak from retaining report-generation memory, leading to memory exhaustion.", "Panorama", S_1113),
    ("PAN-302317", "11.1.13", "all_task process stops responding after a commit, causing the dataplane to reboot repeatedly.", "Dataplane", S_1113),
    ("PAN-302127", "11.1.13", "Active/active HA: adding a 26th floating IP to an aggregate ethernet interface in one vsys breaks IPSec tunnels in another vsys due to rekeying.", "HA", S_1113),
    ("PAN-301942", "11.1.13", "WildFire logs intermittently show an incorrect block action for benign file transfers that downloaded successfully.", "WildFire", S_1113),
    ("PAN-301386", "11.1.13", "BFD echo packets dropped on Vwire interfaces, misdetected as a land attack when BFD source and destination ports differ.", "Networking", S_1113),
    ("PAN-301305", "11.1.13", "HA configurations: all_task process stops responding and the passive firewall reboots.", "HA", S_1113),
    ("PAN-300637", "11.1.13", "VM-Series on Azure: firewall unexpectedly reboots from repeated varrcvr process restarts.", "VM-Series", S_1113),
    ("PAN-300548", "11.1.13", "IKEv2 multiplier for VPN re-authentication does not re-authenticate at expected intervals when both sides initiate rekeying.", "VPN", S_1113),
    ("PAN-299450", "11.1.13", "PAN-OS logrotate does not rotate large log files until cron.daily runs, filling the root partition.", "System", S_1113),

    # PAN-OS 11.2.11
    ("PAN-316911", "11.2.11", "VM-Series on AWS: a newly bootstrapped firewall requires a management restart, relicense, or license push from Panorama to invoke the device certificate.", "VM-Series", S_1121),
    ("PAN-313623", "11.2.11", "Devices with TPM fill /opt/pancfg/mgmt/ssl/private with undeleted .pub_pem files from show device-certificate status, blocking new device-certificate fetch.", "Certificates", S_1121),
    ("PAN-313572", "11.2.11", "VM-Series: dataplane restarts due to a segmentation fault.", "VM-Series", S_1121),
    ("PAN-313258", "11.2.11", "PIM multicast routing fails on appliances with advanced routing enabled.", "Networking", S_1121),
    ("PAN-312618", "11.2.11", "Firewall cannot activate GlobalProtect client software and shows SW LIMIT max-profiles errors, preventing installation.", "GlobalProtect", S_1121),
    ("PAN-311524", "11.2.11", "config-lock is not displayed in the web interface.", "Management", S_1121),
    ("PAN-311074", "11.2.11", "GRE tunnels take significantly longer to establish when the hold timer is set to 10 or higher.", "Networking", S_1121),
    ("PAN-310263", "11.2.11", "VM-Series: enabling TLS 1.3 in a decryption profile prevents access to websites.", "Decryption", S_1121),
    ("PAN-309853", "11.2.11", "FIPS-CC firewalls: editing the GlobalProtect portal returns an error and configuration updates fail.", "GlobalProtect", S_1121),
    ("PAN-309826", "11.2.11", "VM-Series: files from SSL-decrypted sessions are forwarded to WildFire even when Allow Forwarding of Decryption Content is disabled.", "WildFire", S_1121),
    ("PAN-309379", "11.2.11", "logrcvr process stops responding on DPCs, preventing log forwarding.", "Logging", S_1121),
    ("PAN-308902", "11.2.11", "After upgrade, the firewall does not add mTLS sites requiring client-certificate auth via DN list to the ssl-decrypt exclude-cache list.", "Decryption", S_1121),
    ("PAN-311073", "11.2.11", "Panorama-managed HA: firewalls incorrectly update policy rule modified date and MD5 during HA sync commit even when no rule changes were made.", "Panorama", S_1121),
    ("PAN-311250", "11.2.11", "Panorama and Log Collectors: logs from multiple devices are not visible even though Elasticsearch health appears green.", "Panorama", S_1121),

    # PAN-OS 10.2.16
    ("PAN-289102", "10.2.16", "Race condition in predict processing causes a dataplane restart and traffic loss on several firewall platforms.", "Dataplane", S_1021),
    ("PAN-287611", "10.2.16", "After upgrade, incorrect UDP checksum for RTP traffic after NAT and security policy causes dropped packets and silent calls.", "Networking", S_1021),

    # PAN-OS 12.1.7
    ("PAN-CVE-12.1.7", "12.1.7", "Addresses multiple security CVEs: CVE-2026-0256, 0257, 0258, 0259, 0261, 0262, 0263, 0264, 0265, and 0300. Check the PAN security advisories for severity and affected versions.", "Security", S_CVE),
    ("PAN-322815", "12.1.7", "VM-Series on Azure: firewall entered maintenance mode and rebooted after enabling FIPS-CC mode.", "VM-Series", S_1217),
    ("PAN-322681", "12.1.7", "PDF Summary Reports were not generated correctly after upgrading to an affected release.", "Reporting", S_1217),
    ("PAN-322630", "12.1.7", "IKE gateways were not visible in Panorama Templates under Network Profiles from a custom administrator role after upgrade.", "Panorama", S_1217),
    ("PAN-320897", "12.1.7", "Firewall did not detect evasions because TCP checksum offloading was not enabled.", "Threat Prevention", S_1217),
    ("PAN-318288", "12.1.7", "Traffic from Azure to an on-premises firewall was not decrypted and was dropped due to incorrect SPI value identification.", "Decryption", S_1217),
]


def main():
    db = KnownIssuesDB(DB_PATH)
    rows = [
        {"issue_id": i, "fixed_in": v, "description": d, "component": c, "source_url": u}
        for (i, v, d, c, u) in SEED
    ]
    added = db.bulk_add(rows)
    print(f"Seeded {added} issues. {db.stats()}")
    db.close()


if __name__ == "__main__":
    main()
