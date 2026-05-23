# Lumma/Fly Stealer — PCAP Analysis

**Type:** Malware Traffic Analysis  
**Malware Family:** Lumma Stealer / Fly Stealer  
**Source:** TryHackMe / Malware-Traffic-Analysis.net  
**Tool:** Wireshark  

---

## Summary

Analysis of a packet capture containing traffic associated with a Lumma Stealer infection. The investigation identifies the compromised host, the affected user, and the C2 domain that triggered the alert.

---

## Findings

| Artifact | Value |
|---|---|
| Infected IP | `10.1.21.58` |
| Hostname | `DESKTOP-ES9F3ML` |
| MAC Address (victim) | `00:21:5d:c8:0e:f2` |
| Username | `gwyatt` |
| Full Name | Gabriel Wyatt |
| C2 Domain | `white-pepper[.]su` |
| C2 IP | `153.92.1[.]49` |

> IP and domain are defanged following standard threat intel notation.

---

## Investigation Walkthrough

### 1. Identifying the Infected Machine

**Filter used:**
```
tcp.port == 80
```

Reviewed source IPs generating outbound HTTP connections. The internal address `10.1.21.58` showed repeated connections to the external C2 IP, identifying it as the infected host.

---

### 2. MAC Address

Located under the **Ethernet II** header of any packet originating from the infected host.

```
Ethernet II
  Destination: Intel_c8:0e:f2 (00:21:5d:c8:0e:f2)
```

---

### 3. Username

**Protocol:** Kerberos  
**Field path:** `CName → CNameString`

The `CNameString` field in a Kerberos AS-REQ packet contains the authenticating username. The `name-type` field indicates the account type (e.g., `1` = NT-PRINCIPAL for a standard user account).

**Result:** `gwyatt`

---

### 4. Hostname

**Protocol:** NetBIOS Name Service (NBNS)

Filtered for NBNS traffic from the infected IP:
```
nbns && ip.src == 10.1.21.58
```

Located a Name Registration or Query packet. The `<20>` suffix on the hostname indicates the **Server Service**, confirming this is an active Windows workstation.

**Result:** `DESKTOP-ES9F3ML`

---

### 5. Full User Name

**Protocol:** SMB2  

Filtered SMB2 traffic and used Wireshark's Find feature (`Ctrl+F`) to search for the username `gwyatt`. Located a **QueryUserInfo response** containing the full display name.

**Result:** Gabriel Wyatt

---

### 6. C2 Domain

**Methods used:**

**Method 1 — HTTP Host header:**
```
ip.dst == 153.92.1.49 && http
```
Expanded the HTTP request packet and read the `Host:` field directly.

**Method 2 — Reverse DNS lookup:**
```
dns.a == 153.92.1.49
```
Filtered for DNS responses that resolved to the C2 IP, confirming the domain from the DNS layer.

Both methods returned the same result.

**Result:** `white-pepper[.]su`

---

## Tools & Filters Reference

| Purpose                 | Wireshark Filter                            |
| ----------------------- | ------------------------------------------- |
| Find HTTP traffic to C2 | `ip.dst == 153.92.1.49 && http`             |
| Reverse DNS lookup      | `dns.a == 153.92.1.49`                      |
| NBNS hostname           | `nbns && ip.src == <infected_ip>`           |
| Kerberos auth           | `kerberos`                                  |

---

## Notes

- The `.su` TLD (Soviet Union ccTLD) is commonly abused by threat actors due to lax registration oversight — a useful indicator when triaging unfamiliar domains.
- Lumma Stealer is an infostealer sold as MaaS (Malware-as-a-Service) targeting browser credentials, crypto wallets, and session tokens.
