# MITRE ATT&CK Coverage Matrix

Detection coverage across the MITRE ATT&CK Enterprise matrix for this Sentinel lab.

Coverage legend: **[D]** = detection rule deployed  &middot;  **[H]** = hunting query available  &middot;  **[G]** = coverage gap (planned)

---

## Coverage Summary

| Tactic | Techniques in Lab | Coverage Status |
|--------|-------------------|-----------------|
| Initial Access (TA0001) | T1566 (Phishing), T1190 (Exploit Public-Facing Application) | **[H]** hunting only |
| Execution (TA0002) | T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1047 (WMI) | **[D]** PowerShell covered |
| Persistence (TA0003) | T1098 (Account Manipulation), T1136 (Create Account), T1543 (Create/Modify Service) | **[H]** hunting only |
| Privilege Escalation (TA0004) | T1078 (Valid Accounts), T1078.003 (Local Accounts), T1484 (Domain Policy Mod) | **[D]** admin group detection |
| Defense Evasion (TA0005) | T1562 (Impair Defenses), T1070 (Indicator Removal) | **[G]** gap |
| Credential Access (TA0006) | T1110 (Brute Force), T1110.001 (Password Guessing), T1003 (OS Credential Dumping) | **[D]** brute force + failed logons |
| Discovery (TA0007) | T1087 (Account Discovery), T1018 (Remote System Discovery) | **[G]** gap |
| Lateral Movement (TA0008) | T1021 (Remote Services), T1021.001 (RDP), T1021.002 (SMB) | **[H]** hunting only |
| Collection (TA0009) | T1005 (Data from Local System), T1039 (Data from Network Share) | **[G]** gap |
| Command and Control (TA0011) | T1090.003 (Multi-hop Proxy / Tor), T1071 (Application Layer Protocol) | **[D]** Tor detection |
| Exfiltration (TA0010) | T1041 (Exfil Over C2), T1048 (Exfil Over Alternate Protocol) | **[G]** gap |
| Impact (TA0040) | T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery) | **[G]** gap |

**Overall coverage:** 5 techniques with deployed detections, 5 with hunting queries, several known gaps flagged for roadmap.

---

## Deployed Detections (by Technique)

### T1059.001 &mdash; PowerShell

**Rule:** [suspicious-powershell-execution.kql](detections/suspicious-powershell-execution.kql)

**Logic summary:** Flags PowerShell process creations whose command line contains encoded (`-enc`), hidden (`-WindowStyle Hidden`), bypass (`-ExecutionPolicy Bypass`), or download-cradle (`IEX`, `DownloadString`) patterns.

**Data source:** `DeviceProcessEvents` (Microsoft Defender for Endpoint)

**Known limitations:** does not catch AMSI-bypass techniques that strip the flagged substrings. Recommend pairing with AMSI telemetry hunting.

---

### T1078.003 &mdash; Valid Accounts: Local Accounts (Privilege Escalation)

**Rule:** [privilege-escalation-admin-group.kql](detections/privilege-escalation-admin-group.kql)

**Logic summary:** Detects additions to the local Administrators group (Event ID 4732) by accounts that are not on an allowed list.

**Data source:** `SecurityEvent`

**Response:** triggers SOAR playbook to verify change through CAB system; auto-notifies IT Ops.

---

### T1090.003 &mdash; Multi-hop Proxy (Tor)

**Rule:** [tor-exit-node-connection.kql](detections/tor-exit-node-connection.kql)

**Logic summary:** Matches outbound network connections against the public Tor exit node list and Tor directory authority ports (9001, 9030, 9150).

**Data source:** `DeviceNetworkEvents`

**Cross-reference:** paired with the [threat-hunting-scenario-tor](https://github.com/murpheelee/threat-hunting-scenario-tor) writeup.

---

### T1110 &mdash; Brute Force

**Rule:** [brute-force-detection.kql](detections/brute-force-detection.kql)

**Logic summary:** 10+ failed logons (Event ID 4625) from a single source IP followed by a successful logon (Event ID 4624) within 15 minutes.

**Data source:** `SecurityEvent`

**Tuning:** baseline false-positive rate of ~3% from lockout-then-retry legitimate users; suppression on managed service accounts recommended.

---

### T1110.001 &mdash; Password Guessing

**Rule:** [excessive-failed-logons.kql](detections/excessive-failed-logons.kql)

**Logic summary:** Surfaces any source IP exceeding 10 failed logon attempts in 15 minutes (does not require a successful logon to follow).

**Data source:** `SecurityEvent`

**Response:** low severity alert; escalates if the source IP then triggers the T1110 brute force rule.

---

## Detection Roadmap (Planned)

| Priority | Technique | Rule Purpose | Data Source |
|----------|-----------|--------------|-------------|
| P1 | T1003.001 (LSASS Memory) | Detect Mimikatz-style LSASS access | `DeviceProcessEvents` + `DeviceEvents` |
| P1 | T1021.001 (RDP Lateral Movement) | RDP between internal endpoints | `DeviceNetworkEvents` |
| P1 | T1486 (Ransomware) | Mass file rename / Volume Shadow Copy deletion | `DeviceFileEvents` |
| P2 | T1562.001 (Disable Security Tools) | Defender / EDR service stop | `DeviceProcessEvents` |
| P2 | T1098 (Account Manipulation) | Service principal or role changes in Azure AD | `AuditLogs` |
| P3 | T1041 (Exfil Over C2) | Abnormal outbound data volume | `DeviceNetworkEvents` |

---

## ATT&CK Navigator Layer

Export this coverage as a Navigator layer for visualization:

```json
{
  "name": "murpheelee-sentinel-lab",
  "description": "Deployed detection coverage for this Sentinel lab",
  "domain": "enterprise-attack",
  "versions": {
    "attack": "14",
    "navigator": "4.9.0",
    "layer": "4.5"
  },
  "techniques": [
    {"techniqueID": "T1059.001", "score": 100, "color": "#1a9850"},
    {"techniqueID": "T1078.003", "score": 100, "color": "#1a9850"},
    {"techniqueID": "T1090.003", "score": 100, "color": "#1a9850"},
    {"techniqueID": "T1110",     "score": 100, "color": "#1a9850"},
    {"techniqueID": "T1110.001", "score": 100, "color": "#1a9850"},
    {"techniqueID": "T1003.001", "score":  40, "color": "#fee08b"},
    {"techniqueID": "T1021.001", "score":  40, "color": "#fee08b"},
    {"techniqueID": "T1486",     "score":  40, "color": "#fee08b"},
    {"techniqueID": "T1562.001", "score":  30, "color": "#fee08b"},
    {"techniqueID": "T1098",     "score":  30, "color": "#fee08b"},
    {"techniqueID": "T1041",     "score":  20, "color": "#d73027"}
  ],
  "gradient": {
    "colors": ["#d73027", "#fee08b", "#1a9850"],
    "minValue": 0,
    "maxValue": 100
  }
}
```

Load at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/).

---

## Detection Engineering Principles Applied

- **Every rule maps to an ATT&CK technique** &mdash; no orphan detections without a threat justification
- **False positive rates documented** where known, not hidden
- **Tuning exceptions are allowlists, not rule deletions** &mdash; preserves detection intent
- **Gaps are tracked as roadmap items** &mdash; coverage honesty beats false coverage confidence
- **Cross-referenced hunting queries** for techniques not yet promoted to scheduled rules
