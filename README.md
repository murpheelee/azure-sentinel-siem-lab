<p align="center">
  <img src="https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Sentinel"/>
  <img src="https://img.shields.io/badge/Platform-Microsoft%20Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Azure"/>
  <img src="https://img.shields.io/badge/Query-KQL-742774?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="KQL"/>
  <img src="https://img.shields.io/badge/Automation-Logic%20Apps-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Logic Apps"/>
</p>

# Azure Sentinel SIEM Lab

> **Cloud-native SIEM deployment and configuration** — building a fully functional Security Information and Event Management system using Microsoft Sentinel with custom analytics rules, automated incident response, and real-time threat monitoring.

## Objective

Deploy and configure Microsoft Sentinel as a cloud SIEM solution, demonstrating the full lifecycle from workspace creation through log ingestion, custom detection rule authoring, incident investigation, and automated response using SOAR playbooks.

## Lab Architecture

```
         ┌─────────────────────────────────┐
         │       Microsoft Sentinel        │
         │     (SIEM + SOAR Platform)      │
         └───────────────┬─────────────────┘
                         │
         ┌───────────────┴─────────────────┐
         │    Log Analytics Workspace      │
         └───────────────┬─────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
   ┌─────┴─────┐  ┌─────┴──────┐  ┌─────┴─────┐
   │ Windows VM │  │  Azure AD  │  │ NSG Flow  │
   │ Event Logs │  │  Sign-in   │  │   Logs    │
   │  (Sysmon)  │  │   Logs     │  │           │
   └───────────┘  └────────────┘  └───────────┘
```

## Tools & Environment

| Component | Technology | Purpose |
|-----------|-----------|---------|
| SIEM Platform | Microsoft Sentinel | Log aggregation, analytics, incident management |
| Log Storage | Log Analytics Workspace | Centralized log repository |
| Endpoints | Azure VMs (Windows 10/Server) | Log sources generating security events |
| Monitoring | Sysmon | Enhanced endpoint telemetry |
| Identity | Azure Active Directory | Sign-in and audit log source |
| Network | NSG Flow Logs | Network traffic monitoring |
| Automation | Logic Apps (SOAR) | Automated incident response playbooks |
| Query Language | KQL | Custom detection rules and hunting queries |

## Project Phases

### Phase 1: Environment Setup
- Provision Azure subscription and resource group
- Deploy Log Analytics Workspace
- Enable Microsoft Sentinel on the workspace
- Deploy Windows VM endpoints with Sysmon installed
- Configure NSG and diagnostic settings

### Phase 2: Data Connectors & Log Ingestion
- Connect Windows Security Events via AMA (Azure Monitor Agent)
- Enable Azure Active Directory connector for sign-in and audit logs
- Configure NSG Flow Logs ingestion
- Validate data ingestion with KQL queries:

```kql
// Verify Windows Security Events are flowing
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize count() by EventID
| order by count_ desc
| take 10
```

```kql
// Check Azure AD sign-in logs
SigninLogs
| where TimeGenerated > ago(24h)
| summarize count() by ResultType, ResultDescription
| order by count_ desc
```

### Phase 3: Analytics Rules (Custom Detections)

Custom analytics rules built to detect common attack patterns:

| Rule | Severity | MITRE ATT&CK | Description |
|------|----------|---------------|-------------|
| Brute Force Attempt | High | T1110 | Multiple failed logons followed by a success from the same source |
| Possible Privilege Escalation | High | T1078 | User added to administrator group |
| Suspicious PowerShell Execution | Medium | T1059.001 | Encoded or obfuscated PowerShell commands detected |
| Tor Exit Node Connection | High | T1090 | Outbound connections to known Tor exit nodes |
| Excessive Failed Logons | Medium | T1110.001 | More than 10 failed logon attempts in 15 minutes |

**Example: Brute Force Detection Rule**

```kql
// Detect brute force: 10+ failed logons followed by a success
let failedLogons = SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize FailedCount = count(), FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated) by SourceIP = IpAddress, TargetAccount = Account
| where FailedCount >= 10;
let successfulLogons = SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| project SuccessTime = TimeGenerated, SourceIP = IpAddress, TargetAccount = Account;
failedLogons
| join kind=inner successfulLogons on SourceIP, TargetAccount
| where SuccessTime > LastAttempt
| project TargetAccount, SourceIP, FailedCount, FirstAttempt, LastAttempt, SuccessTime
```

### Phase 4: Incident Response & SOAR

Automated response playbooks using Logic Apps:

| Playbook | Trigger | Action |
|----------|---------|--------|
| Isolate Compromised Host | High-severity incident | Disable VM network adapter via Azure API |
| Block Malicious IP | Tor/known-bad IP detected | Add IP to NSG deny rule |
| Notify SOC Team | Any new incident | Send Teams/email notification with incident details |
| Enrich IP Intelligence | New incident with external IP | Query VirusTotal/AbuseIPDB and add as comment |

### Phase 5: Workbook & Dashboard

Custom Sentinel Workbook providing:
- Real-time incident overview (open, closed, severity distribution)
- Geographic visualization of authentication attempts
- Top targeted accounts and source IPs
- Failed vs. successful authentication trends
- Mean time to detection (MTTD) and response (MTTR) metrics

## Key Skills Demonstrated

- Cloud SIEM deployment and configuration
- Log source onboarding and data connector management
- KQL query authoring for detection engineering
- MITRE ATT&CK framework mapping
- SOAR playbook development
- Security dashboard and reporting design
- Incident investigation and triage workflows
