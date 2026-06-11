# Tool Installation

Sequential installation order matters. Wazuh Manager must be up before the agent is deployed. ELK components install in this order: Elasticsearch → Kibana → Logstash, then Filebeat on Kali. Splunk Enterprise must be configured (index + receiving port) before the forwarder is pointed at it.

---

## 1. Wazuh (Ubuntu S1 + Ubuntu S4)

### 1.1 What Wazuh Does in This Lab

Wazuh is the HIDS layer. The **Manager** (S1) runs the analysis engine — it receives data from agents, matches events against rules, maps alerts to MITRE ATT&CK, and orchestrates Active Response. The **Agent** (S4) is the endpoint sensor — it monitors the filesystem in real time, tracks running processes, and executes block commands when the manager instructs it to.

In this lab, Wazuh catches: SSH brute force (Rule 5712 → auto-block), file integrity violations on `/etc/passwd`, `/etc/sudoers`, and `/usr/bin`, and CVEs against installed packages on S4.

### 1.2 Manager Installation — All-in-One (Ubuntu S1)

Wazuh provides an AIO installer that sets up the Manager, Indexer, and Dashboard in a single script. This is the correct approach for a single-node lab.

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

The installer runs through several stages automatically — indexer, manager, Filebeat (internal), and dashboard. At the end it prints the dashboard credentials. **Save them immediately — they are shown once.**

![Wazuh AIO Installation](<https://github.com/Adio20102/Soc-Home-Lab/blob/7040d47cdf28520da6f1f4818e6b081fcb9a2633/screenshots/wazuh%20install%20.png>)

Installation completes in approximately 10–15 minutes. When finished:

```
You can access the web interface https://<wazuh-dashboard-ip>:443
User: admin
Password: <generated>
```

Access the dashboard at `https://192.168.56.40` and confirm it loads.

### 1.3 Agent Installation — Ubuntu (S4)

Agent deployment is generated from the Wazuh dashboard. Navigate to:
**Dashboard → Agents → Deploy New Agent**

Select: Linux → DEB (amd64) → enter Manager IP `192.168.56.40` → set agent name `secure-agent`.

The dashboard generates the exact install command. Copy and run it on S4:

```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.4-1_amd64.deb \
  && sudo WAZUH_MANAGER='192.168.56.40' WAZUH_AGENT_NAME='secure-agent' \
  dpkg -i ./wazuh-agent_4.14.4-1_amd64.deb
```

Start the agent:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

![Wazuh Agent Install Ubuntu](<https://github.com/Adio20102/Soc-Home-Lab/blob/6784ed6613579395d746dbe03bea20630fed4c65/screenshots/wazuh%20agent%20install%20secure%20agent.png>)

Confirm the agent appears in the Wazuh dashboard under **Agents** with status **Active**.

### 1.4 FIM Configuration (Ubuntu S4)

Edit `/var/ossec/etc/ossec.conf` on S4 to configure File Integrity Monitoring with `whodata` — this records the user and process responsible for every file change, not just the checksum delta.

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>300</frequency>
  <scan_on_start>yes</scan_on_start>

  <!-- Real-time monitoring with whodata on critical paths -->
  <directories realtime="yes" check_all="yes" whodata="yes">/etc,/usr/bin,/usr/sbin</directories>
  <directories realtime="yes" check_all="yes" whodata="yes">/bin,/sbin,/boot</directories>

  <!-- Suppress noisy files that change constantly -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <ignore>/etc/mail/statistics</ignore>
  <ignore>/etc/random-seed</ignore>
  <ignore>/etc/random.seed</ignore>
  <ignore>/etc/adjtime</ignore>
  <ignore>/etc/httpd/logs</ignore>
  <ignore>/etc/utmpx</ignore>
  <ignore>/etc/wtmpx</ignore>
  <ignore>/etc/cups/certs</ignore>
  <ignore>/etc/dumpdates</ignore>
  <ignore>/etc/svc/volatile</ignore>
  <ignore type="sregex">.log$|.swp$</ignore>

  <nodiff>/etc/ssl/private.key</nodiff>
  <skip_nfs>yes</skip_nfs>
  <skip_dev>yes</skip_dev>
  <skip_proc>yes</skip_proc>
  <skip_sys>yes</skip_sys>
  <process_priority>10</process_priority>
  <max_eps>50</max_eps>
</syscheck>
```

Restart the agent after saving:

```bash
sudo systemctl restart wazuh-agent
```

> **Why whodata?** Standard FIM only records that a file changed and what the checksum delta was. `whodata` enables the Linux Audit subsystem (`auditd`) integration, which captures the responsible UID, process name, and PID for every monitored file event. In Stage 5B this is what reveals `root via bash` as the actor on each persistence mechanism.

---

## 2. Suricata (Kali)

### 2.1 What Suricata Does in This Lab

Suricata is the NIDS layer. It runs on Kali — the same machine generating the attack — watching all traffic on the host-only interface (`eth1`). It matches live traffic against the Emerging Threats Open ruleset and writes every event to `/var/log/suricata/eve.json` in EVE JSON format. This single file is consumed by both the Splunk Universal Forwarder and Filebeat simultaneously.

### 2.2 Install

```bash
sudo apt update && sudo apt install -y suricata
```

### 2.3 Update Rules

```bash
sudo suricata-update
```

This downloads the Emerging Threats Open ruleset and merges all category files into `/var/lib/suricata/rules/suricata.rules`. The `suricata.yaml` config already points here by default — no manual rule loading needed.

### 2.4 Configure Interface

Edit `/etc/suricata/suricata.yaml` to set the host-only interface:

```yaml
af-packet:
  - interface: eth1     # host-only adapter on Kali

# Confirm the rule path is correct (default after suricata-update)
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
```

### 2.5 Start and Verify

```bash
sudo suricata -l /var/log/suricata/
sudo systemctl enable suricata
sudo systemctl start suricata

# Confirm alerts are flowing
tail -f /var/log/suricata/fast.log
```

> The `configs/suricata.yaml` in this repo contains the relevant sections with comments.

---

## 3. Splunk Enterprise (Ubuntu S2)

### 3.1 What Splunk Does in This Lab

Splunk Enterprise is the primary SIEM. It receives Suricata's `eve.json` events via the Universal Forwarder, stores them in the `linux_server` index, and exposes them for SPL-based search, dashboarding, and alerting. This is where the attack timeline dashboard is built in Stage 8.

### 3.2 Install

Download the `.deb` installer from [splunk.com](https://www.splunk.com/en_us/download/splunk-enterprise.html) and transfer it to S2.

```bash
sudo apt install ./splunk-*.deb
sudo chown -R splunk:splunk /opt/splunk
sudo /opt/splunk/bin/splunk enable boot-start -user splunk --accept-license
sudo systemctl daemon-reload
sudo systemctl start splunk
```

Access Splunk Web at `http://192.168.56.50:8000` and complete the first-run setup.

### 3.3 Configure Receiving Port

**Settings → Forwarding and Receiving → Configure Receiving → New Receiving Port**

Add: `9997`

This is the port the Universal Forwarder will connect to.

### 3.4 Create Index

**Settings → Indexes → New Index**

Index name: `linux_server`

> The index must exist before the forwarder tries to write to it, otherwise events are dropped.

---

## 4. Splunk Universal Forwarder (Kali)

### 4.1 What SUF Does in This Lab

The Universal Forwarder is a lightweight Splunk agent. It tails `/var/log/suricata/eve.json` on Kali and ships new events to Splunk Enterprise on S2 over port 9997. It runs as a persistent service.

### 4.2 Install

Download the `.deb` forwarder package and install on Kali:

```bash
sudo apt install ./splunkforwarder-*.deb
sudo chown -R splunkfwd:splunkfwd /opt/splunkforwarder
sudo /opt/splunkforwarder/bin/splunk enable boot-start -user splunkfwd --accept-license
```

### 4.3 Configure and Start

```bash
cd /opt/splunkforwarder/bin

# Point forwarder at Splunk server
./splunk add forward-server 192.168.56.50:9997

# Monitor Suricata EVE JSON and write to linux_server index
./splunk add monitor /var/log/suricata/eve.json -index linux_server

sudo systemctl daemon-reload
sudo systemctl start splunk
```

### 4.4 Verify Inputs Config

Check `/opt/splunkforwarder/etc/apps/search/local/inputs.conf`:

```ini
[monitor:///var/log/suricata/eve.json]
disabled = false
index = linux_server
```

Confirm events are arriving in Splunk Web:

```spl
index=linux_server | head 10
```

---

## 5. ELK Stack (Ubuntu S5)

### 5.1 What ELK Does in This Lab

ELK is the secondary SIEM. The pipeline is: Filebeat (Kali) → Logstash (S5:5044) → Elasticsearch (S5:9200) → Kibana (S5:5601). It ingests the same Suricata `eve.json` that Splunk receives, allowing a direct comparison of SPL vs KQL, Splunk dashboards vs Kibana visualizations, and SUF vs Filebeat as log shippers.

Install order on S5: **Elasticsearch first, then Kibana, then Logstash.** Kibana needs Elasticsearch's enrollment token to connect; Logstash needs Elasticsearch to be running to ship data to.

### 5.2 Elasticsearch (S5)

Download `elasticsearch-9.4.2-amd64.deb` from [elastic.co](https://www.elastic.co/downloads/elasticsearch) and transfer to S5.

```bash
sudo apt install ./elasticsearch-9.4.2-amd64.deb
```

![Elasticsearch Install](<https://github.com/Adio20102/Soc-Home-Lab/blob/6784ed6613579395d746dbe03bea20630fed4c65/screenshots/ELKsearch%20install.png>)

> **Critical:** The install output shows the generated `elastic` superuser password **once**. Copy it immediately.
> ```
> The generated password for the elastic built-in superuser is: NXa5FUpWc2PTIZUJnQZz
> ```
> To reset later: `/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic`

Configure `/etc/elasticsearch/elasticsearch.yml`:

```yaml
network.host: 192.168.56.70   # listen on host-only interface
http.port: 9200               # REST API port
```

Enable and start:

```bash
sudo systemctl enable elasticsearch.service
sudo systemctl start elasticsearch.service
sudo systemctl status elasticsearch.service
```

### 5.3 Kibana (S5)

```bash
sudo apt install ./kibana-9.4.2-amd64.deb
```

![Kibana Install](<https://github.com/Adio20102/Soc-Home-Lab/blob/6784ed6613579395d746dbe03bea20630fed4c65/screenshots/Kibana%20Install.png>)

Configure `/etc/kibana/kibana.yml`:

```yaml
server.host: 192.168.56.70   # accept connections on host-only interface
server.port: 5601
```

#### Generate Enrollment Token

```bash
cd /usr/share/elasticsearch/bin
./elasticsearch-create-enrollment-token --scope kibana
```

![Generate Enrollment Token](<https://github.com/Adio20102/Soc-Home-Lab/blob/6784ed6613579395d746dbe03bea20630fed4c65/screenshots/Elasticsearch%20create%20enrollement%20token.png>)

Copy the full token string.

#### Connect Kibana to Elasticsearch

Open `http://192.168.56.70:5601` in a browser. You will see the **Configure Elastic to get started** screen. Paste the enrollment token.

![Enter Enrollment Token](<https://github.com/Adio20102/Soc-Home-Lab/blob/46a3d55704c6bec8727c073f197b82f29d0c21b1/screenshots/Enter%20ELKsearch%20enrollement%20token%20in%20kibana.png>)

Generate the Kibana verification code on S5:

```bash
/usr/share/kibana/bin/kibana-verification-code
```

![Kibana Verification Code](<https://github.com/Adio20102/Soc-Home-Lab/blob/46a3d55704c6bec8727c073f197b82f29d0c21b1/screenshots/kibana%20verification%20code.png>)

Enter the code in the browser prompt to complete the connection.

#### Generate and Store Encryption Keys

```bash
cd /usr/share/kibana/bin
./kibana-encryption-keys generate
```

![Generate Encryption Keys](<https://github.com/Adio20102/Soc-Home-Lab/blob/46a3d55704c6bec8727c073f197b82f29d0c21b1/screenshots/Invoke%20kibana%20encryption%20keys.png>)

This outputs three key name/value pairs. Add each to the Kibana keystore:

```bash
./kibana-keystore add xpack.encryptedSavedObjects.encryptionKey
./kibana-keystore add xpack.reporting.encryptionKey
./kibana-keystore add xpack.security.encryptionKey
```

![Add Keys to Keystore](<https://github.com/Adio20102/Soc-Home-Lab/blob/46a3d55704c6bec8727c073f197b82f29d0c21b1/screenshots/add%20kibana%20encryption%20key%20in%20kibana%20keystore.png>)

```bash
sudo systemctl restart kibana
```

> **Why encryption keys?** Without them, Kibana throws warnings on every saved object (dashboards, visualizations). Storing them in the keystore (not `kibana.yml`) keeps credentials out of the config file.

### 5.4 Logstash (S5)

```bash
sudo apt install ./logstash-9.4.2-amd64.deb
```

![Logstash Install](<https://github.com/Adio20102/Soc-Home-Lab/blob/46a3d55704c6bec8727c073f197b82f29d0c21b1/screenshots/Logstash%20install.png>)

Create the pipeline config at `/etc/logstash/conf.d/suricata.conf`:

```
input {
  beats {
    port => 5044          # Filebeat sends here
  }
}

filter {
  # Filebeat's Suricata module already parses EVE JSON
  # No additional filter needed
}

output {
  elasticsearch {
    hosts => ["https://192.168.56.70:9200"]
    user => "elastic"
    password => "NXa5FUpWc2PTIZUJnQZz"   # replace with your generated password
    ssl_verification_mode => "none"
    index => "suricata-%{+YYYY.MM.dd}"
  }
}
```

> `ssl_verification_mode => "none"` is used because the lab environment uses self-signed SSL/TLS certificates, which will cause the Logstash connection to fail if strict validation is turned on. Disabling verification allows Logstash to successfully ship logs over HTTPS without needing to explicitly trust a custom Certificate Authority (CA) chain.

Enable and start Logstash:

```bash
sudo systemctl enable logstash
sudo systemctl start logstash
```

---

## 6. Filebeat (Kali)

### 6.1 What Filebeat Does in This Lab

Filebeat is Elastic's native log shipper. It runs on Kali and tails `eve.json`, parsing it using the built-in Suricata module (which applies ECS field mapping automatically), and ships events to Logstash on S5. It runs alongside the Splunk Universal Forwarder — both read the same file without conflict.

### 6.2 Install

```bash
sudo apt install ./filebeat-9.4.2-amd64.deb
```

![Filebeat Install](<https://github.com/Adio20102/Soc-Home-Lab/blob/46a3d55704c6bec8727c073f197b82f29d0c21b1/screenshots/filebeat%20install.png>)

### 6.3 Enable the Suricata Module

```bash
cd /etc/filebeat/modules.d
ls                                  # all modules listed as .disabled by default
sudo filebeat modules enable suricata
```

![Enable Suricata Module](https://github.com/Adio20102/Soc-Home-Lab/blob/46a3d55704c6bec8727c073f197b82f29d0c21b1/screenshots/enable%20suricata%20module%20in%20filebeat%20modules%20directory.png)

### 6.4 Configure the Suricata Module in Logstash

Edit `/etc/filebeat/modules.d/suricata.yml`:

```yaml
- module: suricata
  eve:
    enabled: true
    var.paths: ["/var/log/suricata/eve.json"]
```

### 6.5 Configure filebeat.yml

Two things to set in `/etc/filebeat/filebeat.yml`:

**Disable the default filestream input** (Module approach used):

```yaml
filebeat.inputs:
  - type: filestream
    enabled: false       # Disabled by default
```

**Enable the default filesbeat module reload** :

```yaml
reload.enabled: true
```

**Set output to Logstash** (Only one output block can be active at a time):

```yaml
output.logstash:
  hosts: ["192.168.56.70:5044"]

# output.elasticsearch is commented out — only one output block works at a time
```

![Filebeat Output Config](<https://github.com/Adio20102/Soc-Home-Lab/blob/46a3d55704c6bec8727c073f197b82f29d0c21b1/screenshots/filebeat%20yml%20config%202%2C%20only%201%20output%20block%20works%20at%20a%20time.png>)

### 6.6 Verify Connection

```bash
sudo filebeat test output
```

Expected output:

```
logstash: 192.168.56.70:5044...
  connection...
    parse host... OK
    dns lookup... OK
    dial up... OK
  TLS... WARN secure connection disabled
  talk to server... OK
```

![Filebeat Test Output](<https://github.com/Adio20102/Soc-Home-Lab/blob/a0991e215a734763ecf7f8eb32be40d6fa83d267/screenshots/verify%20filebeat%20connection.png>)

Enable and start:

```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

### 6.7 Create Data View in Kibana

Go to `http://192.168.56.70:5601` → **Stack Management → Data Views → Create data view**

![Create Data View](<https://github.com/Adio20102/Soc-Home-Lab/blob/a0991e215a734763ecf7f8eb32be40d6fa83d267/screenshots/kibana%20create%20data%20view.png>)

| Field | Value |
|---|---|
| Name | Suricata |
| Index pattern | `suricata-*` |
| Timestamp field | `@timestamp` |

> **Important KQL note:** Due to Filebeat → Logstash ECS field mapping, some field names differ from raw Suricata JSON. Use these field names in KQL:
> - `suricata.eve.event_type` (not `event_type`)
> - `source.ip` (not `src_ip`)
> - `destination.ip` (not `dest_ip`)
> - `suricata.eve.alert.signature` (not `alert.signature`)

---

## 7. TheHive + MISP + Cortex (Ubuntu S3)

> **Status: Work In Progress**
>
> Installation and configuration for TheHive, MISP, and Cortex will be documented here once the IR platform VM is fully set up. This section will cover:
> - TheHive 5 installation and initial org/user setup
> - MISP installation and API key configuration
> - Cortex installation and analyser activation
> - TheHive ↔ MISP ↔ Cortex integration
> - Connecting Wazuh and Splunk alerts as TheHive case sources
