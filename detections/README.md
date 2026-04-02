# KQL Detection Rules

Custom analytics rules for Microsoft Sentinel mapped to MITRE ATT&CK techniques.

| Detection | MITRE ATT&CK | Severity | Data Source |
|-----------|-------------|----------|-------------|
| [Brute Force Detection](brute-force-detection.kql) | T1110 | High | SecurityEvent |
| [Tor Exit Node Connection](tor-exit-node-connection.kql) | T1090.003 | High | DeviceNetworkEvents |
| [Suspicious PowerShell Execution](suspicious-powershell-execution.kql) | T1059.001 | Medium | DeviceProcessEvents |
| [Privilege Escalation — Admin Group](privilege-escalation-admin-group.kql) | T1078.003 | High | SecurityEvent |
| [Excessive Failed Logons](excessive-failed-logons.kql) | T1110.001 | Medium | SecurityEvent |

## Usage

Import these queries into Microsoft Sentinel as **Scheduled Analytics Rules**:
1. Navigate to **Sentinel > Analytics > Create > Scheduled query rule**
2. Paste the KQL query into the rule logic
3. Set the appropriate run frequency and lookback period
4. Configure entity mapping and incident settings
