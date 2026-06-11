# SOC Home Lab — Multi-Tool Detection & Incident Response Environment

A self-built Security Operations Center lab running on VirtualBox across 7 VMs. Covers the full detection lifecycle: network intrusion detection, host-based monitoring, log aggregation across two SIEMs, and incident response workflows — all mapped to MITRE ATT&CK.

The lab simulates a realistic multi-stage attack (recon → exploitation → persistence → brute force) against intentionally vulnerable targets, with every detection layer documented and every alert explained.

---

## Lab Status

| Component | Status |
|---|---|
| Wazuh Manager + Agent | ✅ Complete |
| Suricata NIDS | ✅ Complete |
| Splunk Enterprise + Universal Forwarder | ✅ Complete |
| ELK Stack (Elasticsearch + Logstash + Kibana) + Filebeat | ✅ Complete |
| TheHive + MISP + Cortex | 🔧 In Progress |
| Attack Simulation | 🔧 In Progress |

---

## Network Topology

**Host-Only Network:** `192.168.56.0/24`

| VM | IP | Role |
|---|---|---|
| Kali Linux | 192.168.56.10 | Attacker — Suricata, Splunk UF, Filebeat |
| Metasploitable 2 | 192.168.56.20 | Victim — intentionally vulnerable, no agent |
| Ubuntu S4 | 192.168.56.30 | Monitored Endpoint — Wazuh Agent |
| Ubuntu S1 | 192.168.56.40 | Wazuh Manager + Dashboard |
| Ubuntu S2 | 192.168.56.50 | Splunk Enterprise (Primary SIEM) |
| Ubuntu S3 | 192.168.56.60 | TheHive + MISP + Cortex (IR Platform) |
| Ubuntu S5 | 192.168.56.70 | ELK Stack — Elasticsearch + Logstash + Kibana |

**Total resources:** 20GB RAM, 12 cores across 7 VMs

---

## Architecture Overview

```
ATTACK LAYER
  Kali (192.168.56.10)
      │
      ├── Suricata (NIDS) — watches all traffic on host-only interface
      │       │
      │       ├── eve.json → Splunk Universal Forwarder → Splunk Enterprise S2
      │       │                                           index: linux_server
      │       │
      │       └── eve.json → Filebeat → Logstash → Elasticsearch → Kibana S5
      │                                             index: suricata-*
      │
      └── Metasploit → exploits → Metasploitable (192.168.56.20)

ENDPOINT LAYER
  Ubuntu S4 (192.168.56.30)
      └── Wazuh Agent → FIM + whodata + Active Response + Vuln Detection
              └── Wazuh Manager S1 (192.168.56.40)
                      └── Wazuh Dashboard → MITRE ATT&CK tagged alerts

IR LAYER (WIP)
  Ubuntu S3 (192.168.56.60)
      └── TheHive ←→ MISP ←→ Cortex
              ↑ cases fed from Wazuh + Splunk alerts
```

---

## Detection Layers

| Layer | Tool | What It Detects |
|---|---|---|
| Network (NIDS) | Suricata | Nmap scans, exploit attempts, C2 sessions, brute force |
| Host (HIDS) | Wazuh Agent | File changes, new accounts, privilege escalation, process activity |
| Log Management | Wazuh Manager | Alert correlation, MITRE mapping, Active Response orchestration |
| Primary SIEM | Splunk Enterprise | SPL-based search and dashboards on Suricata network data |
| Secondary SIEM | ELK / Kibana | KQL-based search and dashboards — comparison reference against Splunk |
| IR Platform | TheHive + MISP | Case management, IOC enrichment, IR lifecycle tracking *(WIP)* |

---

## Attack Simulation Summary

A 9-stage simulated attack covering the full kill chain against two targets.

| Stage | Technique | MITRE | Detected By |
|---|---|---|---|
| 1 — Recon | Nmap service scan | T1046 | Suricata → Splunk + ELK |
| 2 — vsftpd Backdoor | Exploit public-facing app | T1190 | Suricata + Wazuh |
| 3 — Samba RCE | Exploit + command injection | T1190, T1059 | Suricata → Splunk + ELK |
| 4 — Post-Exploitation | Account creation on victim | T1136, T1098 | Suricata (C2 session) |
| 5A — SSH Brute Force | Credential brute force on S4 | T1110 | Wazuh Rule 5712 + Active Response |
| 5B — FIM: Persistence | /etc/passwd, sudoers, backdoor binary | T1136, T1548, T1105 | Wazuh FIM + whodata |
| 5C — Vuln Detection | CVE scan on S4 packages | — | Wazuh Vulnerability Detection |
| 6 — Threat Intel | IOC creation and enrichment | — | MISP + Cortex *(WIP)* |
| 7 — Incident Response | Full case lifecycle | — | TheHive *(WIP)* |
| 8 — Splunk Dashboard | Attack timeline visualization | — | Splunk Enterprise |
| 9 — Kibana Dashboard | SIEM comparison dashboard | — | ELK / Kibana |

---

## Resume Proof Points

| Capability | Tool | Evidence |
|---|---|---|
| Network Intrusion Detection | Suricata | Scan, vsftpd, Samba, SSH brute force signatures detected and logged |
| Host Intrusion Detection + FIM | Wazuh Agent | `/etc/passwd`, `/etc/sudoers`, `/usr/bin` monitored realtime with whodata |
| Active Response | Wazuh | Auto-blocked brute forcing IP via ufw on monitored endpoint |
| Vulnerability Management | Wazuh | CVE scan correlated against installed packages on S4 |
| Primary SIEM | Splunk Enterprise | SPL queries, `linux_server` index, saved dashboards |
| Secondary SIEM | ELK / Kibana | KQL queries, `suricata-*` index, Kibana dashboards |
| Dual SIEM Comparison | Splunk vs ELK | Same Suricata data ingested via two separate pipelines, compared |
| Log Pipeline (Elastic) | Filebeat → Logstash → ES | Filebeat Suricata module, Logstash pipeline config, ECS field mapping |
| Log Forwarding (Splunk) | Splunk Universal Forwarder | `eve.json` monitored and shipped to Splunk Enterprise |
| Threat Intelligence | MISP + Cortex | IOC creation, ATT&CK galaxy tagging, Cortex enrichment *(WIP)* |
| Incident Management | TheHive | Full IR lifecycle from alert to close *(WIP)* |
| Exploit Knowledge | Metasploit | vsftpd 2.3.4 backdoor (CVE-2011-2523), Samba RCE (CVE-2007-2447) |
| MITRE ATT&CK Mapping | Throughout | T1046, T1190, T1059, T1136, T1110, T1548, T1105 |

---

## Repository Structure

```
soc-home-lab/
├── README.md
├── docs/
│   ├── lab-setup.md            ← VM specs, network topology, architecture
│   ├── tool-installation.md    ← Step-by-step install for all tools
│   ├── attack-simulation.md    ← All 9 stages with commands, queries, detections
│   └── full-walkthrough.md     ← Narrative analyst write-up (post-simulation)
├── configs/
│   ├── ossec.conf              ← Wazuh FIM syscheck config
│   ├── suricata.yaml           ← Suricata interface + rule config
│   ├── filebeat.yml            ← Filebeat input + Suricata module
│   ├── suricata.conf           ← Logstash pipeline config
│   ├── inputs.conf             ← Splunk UF monitored inputs
│   └── netplan-template.yaml   ← Static IP config for Ubuntu VMs
└── screenshots/
    ├── wazuh-setup/
    ├── stage1-recon/
    ├── stage2-vsftpd/
    ├── stage3-samba/
    ├── stage4-postex/
    ├── stage5a-bruteforce/
    ├── stage5b-fim/
    ├── stage5c-vulndetect/
    ├── stage6-misp/
    ├── stage7-thehive/
    ├── stage8-splunk/
    └── stage9-elk/
```

---

## Documentation

| File | Description |
|---|---|
| [Lab Setup](docs/lab-setup.md) | VM specifications, network topology, netplan config, architecture rationale |
| [Tool Installation](docs/tool-installation.md) | Full install walkthrough — Wazuh, Suricata, Splunk, ELK, TheHive/MISP |
| [Attack Simulation](docs/attack-simulation.md) | All 9 attack stages with commands, detection tables, SPL and KQL queries |
| [Full Walkthrough](docs/full-walkthrough.md) | Analyst narrative — detection logic, triage decisions, timeline, gaps |

---

## Tools & Technologies

`Wazuh` `Suricata` `Splunk Enterprise` `Elasticsearch` `Logstash` `Kibana` `Filebeat`
`Splunk Universal Forwarder` `Metasploit` `Hydra` `TheHive` `MISP` `Cortex`
`VirtualBox` `Ubuntu 22.04` `Kali Linux` `Metasploitable 2`
`MITRE ATT&CK` `CVE-2011-2523` `CVE-2007-2447`
