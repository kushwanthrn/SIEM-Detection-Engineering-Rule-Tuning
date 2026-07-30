# SIEM Detection Engineering with Rule Tuning
*Building, Testing & Tuning Splunk Correlation Rules Against Simulated Attack Techniques*

## Overview

This project builds directly on [End-to-End SOC Investigation](https://github.com/kushwanthrn/SOC-End-to-End-Investigation), which demonstrated that a simulated fileless PowerShell intrusion could be fully reconstructed via retrospective log analysis — but was never detected in real time, since no correlation rules or alerting existed in that lab. This project closes that gap.

Five Splunk correlation rules were designed, tested, and tuned against the same attack chain: initial execution, dual persistence mechanisms, network exfiltration, and reconnaissance. Each rule was validated using **atomic testing** — a true-positive script replicating the exact malicious technique, and a false-positive script replicating benign lookalike activity — to confirm the rule discriminates correctly rather than simply pattern-matching on surface features. Every rule was also confirmed to fire as a genuine, live, scheduled Splunk alert, not just a search that logically *could* alert.

**📄 [Full Write-Up (PDF)](./SIEM%20Detection%20Engineering%20Write-Up.pdf)**

## Key Highlights

- **5 correlation rules**, covering 8 distinct MITRE ATT&CK techniques across Execution, Persistence, Discovery, and Exfiltration
- **Every rule verified operational** — confirmed firing as a live, scheduled alert via Splunk's Triggered Alerts log, not just a passing test query
- **Real tuning iterations, fully documented** — including a caught attacker evasion technique (abbreviated PowerShell flags bypassing a naive string match) and a detection-logic redesign (a wildcard bug plus an unscalable process-name blacklist, both replaced with content-based detection)
- **A clear methodology finding:** every rule designed *after* switching from blacklist-style to content/behavior-based detection was correctly tuned on the first attempt — a genuinely transferable lesson, not a coincidence
- **Rule 5 uses correlated, multi-event detection** (Splunk's `transaction` command, grouping discovery commands by shared parent process within a 15-second window) — a more advanced technique than single-event pattern matching

## Detection Rules Summary

| Rule | MITRE ATT&CK | Tuning Iterations |
|---|---|---|
| 1 — PowerShell Download Cradle | T1059.001, T1105, T1620 | 1 — abbreviated PowerShell flag evasion |
| 2 — Registry Run Key Persistence | T1547.001 | 2 — wildcard bug + blacklist-to-content-based redesign |
| 3 — Scheduled Task Creation | T1053.005 | 0 — correctly tuned on first design |
| 4 — Outbound Connection, Non-Standard Port | T1048.003, T1071 | 0 — correctly tuned on first design |
| 5 — Rapid Discovery Command Burst | T1033, T1069, T1082, T1087.001, T1016, T1016.001, T1049, T1057 | 0 — correctly tuned on first design |

## Lab Environment

Reuses the isolated lab from Project 1: Kali Linux (attacker) + Windows 10 (victim) on a sealed VirtualBox NAT network, Sysmon (SwiftOnSecurity config) forwarding telemetry to Splunk via Universal Forwarder. Unlike Project 1 (Splunk Free tier, no alerting), this project used a **60-day Splunk Enterprise Trial** license specifically to enable live scheduled alerting and correlation searches.

## Repository Contents

Each rule folder contains its full evidence set — Splunk query screenshots (numbered to match the write-up's figures) and the raw Sysmon logs for both the true-positive and false-positive test:

```
├── SIEM-Detection-Engineering-Write-Up.pdf   # Full write-up: methodology, all 5 rules, tuning summary
├── Rule1-PowerShell-Download-Cradle/
├── Rule2-Registry-Run-Key-Persistence/
├── Rule3-Scheduled-Task-Creation/
├── Rule4-Outbound-Non-Standard-Port/
└── Rule5-Rapid-Discovery-Command-Burst/
```

## Skills Demonstrated

Splunk SPL (correlation searches, `transaction`/`stats`, alerting) · Detection engineering & rule tuning · False-positive analysis · MITRE ATT&CK mapping · Atomic/isolated testing methodology · Technical documentation

---

*Part of a SOC analyst portfolio. See also: [End-to-End SOC Investigation](https://github.com/kushwanthrn/SOC-End-to-End-Investigation) · Network Threat Detection (Wireshark) — in progress.*
