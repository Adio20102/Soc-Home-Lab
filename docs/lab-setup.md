# Lab Setup
 
## Overview
 
This lab is built on VirtualBox using a host-only network, isolating all attack traffic to a private `192.168.56.0/24` segment. No attack traffic touches the host's real network. Seven VMs cover every layer of a SOC: attacker, victim, monitored endpoint, HIDS, two SIEMs, and an IR platform.
 
---
 
## VM Specifications
 
| VM | Hostname | Username | IP | RAM | Cores | Storage | Role |
|---|---|---|---|---|---|---|---|
| Kali Linux | kali | root | 192.168.56.101 | 2GB | 2 | existing | Attacker + Suricata + SUF + Filebeat |
| Metasploitable 2 | metasploitable | msfadmin | 192.168.56.102 | 512MB | 1 | existing | Victim — no agent |
| Ubuntu S4 | endpoint-01 | endpointadmin | 192.168.56.107 | 1.5GB | 1 | 15GB | Monitored Endpoint — Wazuh Agent |
| Ubuntu S1 | wazuhmachine | admin | 192.168.56.104 | 4GB | 2 | 48GB | Wazuh Manager + Dashboard |
| Ubuntu S2 | splunk-server | splunkadmin | 192.168.56.105 | 4GB | 2 | 50GB | Splunk Enterprise |
| Ubuntu S3 | ir-server | iradmin | 192.168.56.106 | 4GB | 2 | 50GB | TheHive + MISP + Cortex |
| Ubuntu S5 | elk-server | elkadmin | 192.168.56.108 | 4GB | 2 | 50GB | ELK Stack |
 
**Total:** 20GB RAM, 12 cores
 
> Password is the same across all Ubuntu VMs for lab simplicity.
 
---
 
## Network Topology
 
```
HOST-ONLY NETWORK: 192.168.56.0/24
(no traffic leaves this segment)
 
192.168.56.101  Kali          ──┐
192.168.56.102  Metasploitable  │  All on same /24
192.168.56.107  Ubuntu S4       │  VirtualBox Host-Only
192.168.56.104  Ubuntu S1       │  Adapter: vboxnet0
192.168.56.105  Ubuntu S2       │
192.168.56.106  Ubuntu S3     ──┘
192.168.56.108  Ubuntu S5
```
 
Each Ubuntu VM has **two network adapters**:
- **Adapter 1 (enp0s3):** NAT — outbound internet for package installs
- **Adapter 2 (enp0s8):** Host-Only — lab traffic, static IP
---
 
## Static IP Configuration
 
On each Ubuntu VM, edit `/etc/netplan/50-cloud-init.yaml`:
 
```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true          # NAT adapter — internet access
    enp0s8:
      dhcp4: no
      addresses:
        - 192.168.56.XX/24  # replace XX per VM (107, 104, 105, 106, 108)
```
 
Apply the config:
 
```bash
sudo netplan apply
```
 
Verify:
 
```bash
ip a show enp0s8
ping 192.168.56.1  # ping host
```
 
---
 
## Architecture Rationale
 
Every tool in this lab exists for a specific reason. This section explains the detection philosophy behind each component.
 
### Suricata — Network Intrusion Detection (NIDS)
 
Suricata runs on **Kali** (the attacker machine), not a dedicated sensor VM. This is intentional — placing it on the same host as the attack traffic means it sees everything on the host-only interface before any VM-level filtering. Suricata watches for known attack signatures using the Emerging Threats ruleset and logs all alerts to `eve.json` (EVE JSON format). This log file is the single source of truth for both SIEMs.
 
Suricata answers: **what crossed the network?**
 
### Wazuh — Host Intrusion Detection (HIDS)
 
Wazuh Agent runs on **Ubuntu S4** (the monitored endpoint). It watches the filesystem in real time using Linux Audit (`auditd`) — this is the `whodata` mode, which records not just what changed but who changed it and which process was responsible. When the SSH brute force runs, Wazuh's analysis engine matches the pattern against Rule 5712 and triggers Active Response, which calls `ufw` to block the source IP automatically.
 
Wazuh answers: **what happened on the endpoint, who did it, and did we respond?**
 
### Splunk Enterprise — Primary SIEM
 
Splunk receives Suricata's `eve.json` via the Universal Forwarder. It is the primary search and dashboard platform for this lab. SPL (Search Processing Language) is used for alert queries, timecharts, and the final attack dashboard. Splunk's index (`linux_server`) stores the raw Suricata events.
 
Splunk answers: **how do I search, correlate, and visualize network alerts at scale?**
 
### ELK Stack — Secondary SIEM
 
ELK (Elasticsearch + Logstash + Kibana) receives the same `eve.json` via Filebeat. It serves as a direct comparison point against Splunk — same data, different query language (KQL), different visualization workflow. Having both SIEMs in one lab demonstrates that SIEM fundamentals transfer across platforms and that the pipeline architecture (shipper → processor → storage → UI) is consistent regardless of vendor.
 
ELK answers: **how does the same data look and behave in the Elastic stack?**
 
### TheHive + MISP + Cortex — IR Platform *(WIP)*
 
TheHive provides structured incident case management. MISP stores and shares threat intelligence (IOCs, CVEs, MITRE tags). Cortex runs automated enrichment jobs (e.g. hash lookups, IP reputation checks). Together they simulate the IR lifecycle: an analyst receives an alert, creates a case in TheHive, tags observables, imports threat context from MISP, runs Cortex analysers, and closes the case with a documented timeline.
 
This layer answers: **how does a real SOC track and close an incident?**
 
### Why Metasploitable Has No Agent
 
This is a deliberate detection gap. In a real network, not every host will have an EDR agent. Metasploitable represents unmonitored legacy infrastructure — you can exploit it, post-exploit it, and create accounts on it, and Wazuh will never see it. Only Suricata (network layer) catches what happens to it. This gap is documented in the full walkthrough as a realistic limitation and an argument for defence-in-depth.
 
---
 
## Log Flow Summary
 
```
Suricata (Kali) → eve.json
    ├── Splunk Universal Forwarder → Splunk Enterprise S2 (index: linux_server)
    └── Filebeat (Suricata module) → Logstash S5:5044 → Elasticsearch S5:9200 → Kibana S5:5601
 
Wazuh Agent (S4) → Wazuh Manager S1 → Wazuh Dashboard (https://192.168.56.104)
 
TheHive (S3) ←→ MISP (S3) ←→ Cortex (S3)   [WIP]
```
 
