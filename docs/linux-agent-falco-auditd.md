# Linux Agent Setup - Falco and auditd (ubnsrv-agent)

## Overview

ubnsrv-agent is an Ubuntu 22.04.5 LTS server running three telemetry sources:
- Wazuh Agent v4.14.5 (log forwarding)
- Falco 0.43.1 (runtime threat detection via eBPF)
- auditd (Linux syscall auditing)

## Wazuh Agent

### Installation

```bash
WAZUH_MANAGER="<manager-ip>" apt-get install wazuh-agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

Version installed: **v4.14.5 (rc1)**

### Verify Connection

```bash
# On the agent
/var/ossec/bin/wazuh-control status

# On the Manager
sudo /var/ossec/bin/agent_control -lc
# ID: 001, Name: ubnsrv-agent, IP: any, Active
```

## Falco

### Version

```
Falco version: 0.43.1 (x86_64)
Engine version: 0.58.0
Libs version: 0.23.2
Plugin API version: 3.12.0
Driver API version: 8.0.0
Default driver version: 9.1.0+driver
```

### Output Configuration

Falco is configured to write JSON alerts to a local file. The relevant section from `/etc/falco/falco.yaml`:

```yaml
file_output:
  enabled: true
  keep_alive: true
  filename: /var/log/falco/falco_events.json
```

`keep_alive: true` keeps the file handle open for continuous writes, which improves performance and avoids file rotation issues.

### Rules

Active Falco config files:
- `/etc/falco/falco.yaml` (main config)
- `/etc/falco/config.d/engine-kind-falcoctl.yaml`
- `/etc/falco/config.d/falco.container_plugin.yaml`

Custom rules in `/etc/falco/rules.d/`:
- `falco-incubating_rules.yaml` (community incubating rules, includes XZ backdoor pattern)
- `falco-linux-enchance.yaml` (Linux-specific enhancements)

No modifications to the default Falco ruleset were made. The detections in this implementation use the rules as distributed.

### Wazuh Agent - Falco Log Collection

From `/var/ossec/etc/ossec.conf` on ubnsrv-agent:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/falco/falco_events.json</location>
</localfile>
```

`log_format: json` activates Wazuh's built-in JSON decoder. No custom decoder is required. Falco's JSON output fields (`rule`, `priority`, `hostname`, `output`) are parsed automatically and matched by the custom Falco rules (117000-117003).

### Verify Falco Alerts Reaching Wazuh

```bash
# Check Falco is writing alerts
tail -f /var/log/falco/falco_events.json

# Check Wazuh Agent is reading the file
grep -i "falco" /var/ossec/logs/ossec.log | tail -10
```

In Wazuh Dashboard, filter by `rule.groups: falco` and agent `ubnsrv-agent`.

## auditd

### Version

auditd from Ubuntu 22.04 package repository. Service active since 2026-05-18.

### Audit Rules

A MITRE ATT&CK-mapped auditd ruleset is loaded on this server. The ruleset covers over 200 rules across categories including credential access, privilege escalation, persistence, lateral movement, and exfiltration.

Full ruleset documented in `configs/linux/auditd-rules.conf`.

Key audit keys relevant to custom Wazuh rules:

| Audit Key                                    | What It Covers                                                   |
|----------------------------------------------|------------------------------------------------------------------|
| etcpasswd                                    | /etc/passwd and /etc/shadow access                               |
| shadow_access                                | /etc/shadow read/write/execute                                   |
| rootcmd                                      | Commands executed as root by non-root users (euid=0, auid>=1000) |
| susp_activity                                | Execution of curl, wget, nc, nmap, and similar tools             |
| recon                                        | whoami, id, hostname, uname                                      |
| priv_esc                                     | sudo, su, SUID binaries                                          |
| remote_shell                                 | bash making outbound network connections                         |
| T1011_Exfiltration_Over_Other_Network_Medium | Raw socket creation                                              |

Load rules:
```bash
sudo auditctl -R /etc/audit/rules.d/audit.rules
sudo auditctl -l  # verify
```

### Wazuh Agent - auditd Log Collection

From `/var/ossec/etc/ossec.conf` on ubnsrv-agent:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

`log_format: audit` activates Wazuh's built-in auditd decoder, which parses the Linux audit record format (type=SYSCALL, type=PATH, type=EXECVE records).

### Verify auditd Events Reaching Wazuh

```bash
# Trigger a monitored event
cat /etc/shadow

# Confirm it appears in audit log
ausearch -k etcpasswd -ts recent

# Check in Wazuh Dashboard
# Filter: rule.groups: auditd, agent: ubnsrv-agent
# Expected: Rule 210100 firing at level 8
```

### Important Note on Rule 80700

All auditd SYSCALL events match Wazuh's built-in rule 80700 ("Audit: Messages grouped") at level 0. This means no alert is generated unless a custom child rule explicitly matches the `audit.key` field. The custom rules in this implementation (210100-210114) are child rules of 80700. Without them, auditd events are indexed but invisible in Security Events.

## Full ossec.conf - Relevant Sections

```xml
<ossec_config>

  <client>
    <server>
      <address>MANAGER_IP_REDACTED</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/falco/falco_events.json</location>
  </localfile>

  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

</ossec_config>
```
