# Full Walkthrough

> **Status: Pending**
>
> This document is written after the attack simulation is fully executed. It is a narrative analyst write-up — not a replication guide. Where `attack-simulation.md` documents *how* to run each stage, this document records *what was observed*, *why each detection fired*, and *what an analyst would do with that information*.
>
> Fill this in after completing all 9 stages with real timestamps, real alert outputs, and real observations from the Wazuh dashboard, Splunk, and Kibana.

---

## Document Structure (to complete post-simulation)

### 1. Incident Summary

One paragraph written as an executive summary. Covers: what happened, what was targeted, what was detected, and what was contained. Written in past tense as if the incident is closed.

### 2. Environment at Time of Incident

Brief table: which services were active, which dashboards were being monitored, and the lab network state at simulation start.

### 3. Attack Timeline

The complete unified timeline — every detection event mapped to a timestamp. Format:

| Timestamp | Stage | MITRE | Source | Alert/Event | Action Taken |
|---|---|---|---|---|---|
| HH:MM:SS | S1 — Recon | T1046 | Suricata | ET SCAN Nmap SYN Sweep | Noted — attacker IP logged |
| HH:MM:SS | S2 — vsftpd | T1190 | Suricata | vsftpd backdoor signature | Noted |
| HH:MM:SS | S2 — vsftpd | T1190 | Suricata | Port 6200 session open | Noted |
| HH:MM:SS | S3 — Samba | T1190, T1059 | Suricata | Samba RCE signature | Noted |
| HH:MM:SS | S5A | T1110 | Wazuh | Rule 5712 — auth failures | Active Response triggered |
| HH:MM:SS | S5A | T1110 | Wazuh | Active Response — IP blocked | 192.168.56.10 blocked via ufw |
| HH:MM:SS | S5B | T1136 | Wazuh FIM | /etc/passwd modified (whodata) | Flagged for investigation |
| HH:MM:SS | S5B | T1548 | Wazuh FIM | /etc/sudoers modified (whodata) | Flagged for investigation |
| HH:MM:SS | S5B | T1105 | Wazuh FIM | /usr/bin/malicious_script created | Flagged for investigation |

*(Fill in actual timestamps from screenshots during simulation)*

### 4. Stage-by-Stage Analyst Narrative

For each stage, write 1–2 paragraphs from the analyst's perspective. Not "I ran nmap" — but "At [time], the network sensor registered a burst of SYN packets originating from 192.168.56.10 targeting 192.168.56.20 across multiple ports. The pattern matched Suricata rule ET SCAN Nmap SYN Sweep, indicating active service discovery..."

**Stage 1 — Reconnaissance**

*(write here after simulation)*

**Stage 2 — vsftpd Backdoor**

*(write here after simulation)*

**Stage 3 — Samba RCE**

*(write here after simulation)*

**Stage 4 — Post-Exploitation**

*(write here after simulation)*

**Stage 5A — SSH Brute Force + Active Response**

*(write here after simulation — focus on: what Rule 5712 threshold is, how the Active Response chain works, what the block log looks like, how Hydra timeouts confirmed the block was effective)*

**Stage 5B — FIM and Persistence**

*(write here after simulation — focus on: which files were monitored and why, what whodata revealed, how the three MITRE techniques map to the three file operations)*

**Stage 5C — Vulnerability Detection**

*(write here after simulation)*

**Stage 6 — Threat Intelligence (MISP)**

*(write here after WIP completion)*

**Stage 7 — Incident Case (TheHive)**

*(write here after WIP completion)*

### 5. Detection Coverage Map

Table showing which attacks were caught at which layer — and critically, what was *not* caught and why.

| Attack | Network (Suricata) | Host (Wazuh) | Notes |
|---|---|---|---|
| Nmap scan | ✅ ET SCAN rule | ❌ | Recon is network-only |
| vsftpd exploit | ✅ vsftpd signature | ❌ | No agent on Metasploitable |
| Samba RCE | ✅ Samba RCE rule | ❌ | No agent on Metasploitable |
| Account creation on Metasploitable | ⚠️ C2 session only | ❌ | Account creation invisible to Suricata |
| SSH brute force on S4 | ✅ SSH alert | ✅ Rule 5712 + block | Both layers catch it |
| /etc/passwd modification | ❌ | ✅ FIM + whodata | Host-only event |
| /etc/sudoers modification | ❌ | ✅ FIM + whodata | Host-only event |
| Malicious binary in /usr/bin | ❌ | ✅ FIM + whodata | Host-only event |

### 6. Gaps and Limitations

Honest analysis of what this lab setup does not detect and why. Topics to cover:

- Metasploitable has no Wazuh Agent — account creation, privilege escalation, and lateral movement on that host are invisible to HIDS. In a production environment this would be unacceptable; here it illustrates why coverage matters.
- Suricata relies on signatures — a zero-day or custom C2 protocol not in the ET ruleset would not alert.
- The brute force was detected because it was noisy (full rockyou.txt). A slow, low-volume password spray would not trigger Rule 5712's threshold.
- TheHive and MISP are not integrated with Splunk or Wazuh in this lab — alerts do not automatically become cases. In a production SOC this integration would be critical.

### 7. Lessons Learned

4–5 sentences covering what this lab demonstrated that is directly applicable to a real SOC environment. Write as if debriefing a team. Cover: value of layered detection (network + host), the difference between what a SIEM sees vs what an EDR sees, the operational value of Active Response, and what you would add if this were a production environment.

*(write here after simulation is complete)*
