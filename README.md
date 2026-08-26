# Endpoint Detection Engineering with Wazuh, Falco, Sysmon, and Auditd

Security monitoring implementation developed for an assurance services client as part of a two month security engineering engagement. The implementation covers endpoint telemetry collection, centralized log management, and detection engineering across Linux and Windows server environments.

This repository documents the technical architecture, configurations, detection rules, and validation testing conducted during the engagement. The lab environment was built on cloned infrastructure prior to production deployment.

Client identity, addresses, and agent addresses are redacted. Hostnames are the lab names and are kept as written, because the agent IDs, the sample alerts, and the test results all refer to them.

## Engagement Context

**Role:** Security Engineer (PT. Visionet Data Internasional)
**Client:** Assurance Services Client
**Duration:** 2 months
**Scope:** Security monitoring implementation using Wazuh as the central SIEM, covering Linux and Windows server endpoints with multi source telemetry integration

The implementation was preceded by a Proof of Concept phase to validate detection coverage and dashboard functionality before production rollout. This repository reflects the configurations and rules developed and tested during that process.

## Placeholders

Every value that belonged to the environment is redacted. Replace each of these before
using anything here.

| Placeholder      | What it is                                    | Where it appears                                    |
|------------------|-----------------------------------------------|-----------------------------------------------------|
| `MANAGER_IP`     | address of the Wazuh Manager                  | the `<address>` element in both agent configurations |
| `<AGENT_IP>`     | address of the endpoint that raised the alert | the `agent.ip` field in `sample_alerts/`             |
| `<ATTACKER_IP>`  | external source address in a captured alert   | the SSH brute force sample                           |

`MANAGER_IP` carries no angle brackets on purpose. It sits inside the `<address>` element
of an XML configuration file, where angle brackets would make the file invalid, and a bare
`MANAGER_IP` is also what the stock Wazuh agent configuration ships with.

Three kinds of value are deliberately left as written. **Hostnames** (`ubnsrv-aio`,
`ubnsrv-agent`, `winsrv-agent`) are lab names rather than customer names, and the agent IDs
and test results are written against them. **Versions** are pinned deliberately, since a
detection built on Sysmon v15.20 and Falco 0.43.1 is only reproducible against those
versions. **Audit keys and rule IDs** are structural, because the auditd ruleset and the
Wazuh rules have to agree on them.

## Architecture

The same diagram is kept as a standalone file in `diagrams/architecture.mermaid`, so it can
be rendered outside this page.

```mermaid
graph TB
    subgraph AIO["Wazuh All in One, Central SIEM"]
        WM[Wazuh Manager]
        WI[Wazuh Indexer / OpenSearch]
        WD[Wazuh Dashboard]
        WM --> WI --> WD
    end

    subgraph LINUX["Linux Server Endpoint"]
        LA[Wazuh Agent v4.14.5]
        Falco[Falco 0.43.1]
        Auditd[auditd]
        Falco -->|JSON alerts| LA
        Auditd -->|audit.log| LA
    end

    subgraph WIN["Windows Server 2019 Endpoint"]
        WA[Wazuh Agent v4.14.5]
        Sysmon[Sysmon v15.20]
        Sysmon -->|Event Log| WA
    end

    LA -->|port 1514 TLS| WM
    WA -->|port 1514 TLS| WM
```

## Environment Inventory

| Host         | Role                              | OS                                              | Wazuh Version | Agent ID     | Status |
|--------------|-----------------------------------|-------------------------------------------------|---------------|--------------|--------|
| ubnsrv-aio   | Wazuh Manager, Indexer, Dashboard | Linux                                           | v4.14.5       | 000 (server) | Active |
| ubnsrv-agent | Linux Server Endpoint             | Ubuntu 22.04.5 LTS, Kernel 5.15.0-179-generic   | v4.14.5       | 001          | Active |
| winsrv-agent | Windows Server Endpoint           | Windows Server 2019 Standard (Build 10.0.17763) | v4.14.5       | 002          | Active |

Two naming layers exist and both appear in the evidence. The **agent name** is what Wazuh
registers and what every alert carries in `agent.name`, and those are the names in the
table above. The **operating system hostname** is different on both endpoints: the Linux
host reports `ubnsrv-falco` in `uname` and in the syslog header of its own sshd events, and
the Windows host reports `winsrv-agn` as its computer name in Sysmon events.

Searching alert data by `agent.name` finds everything; searching by the hostname finds only
what carries a raw log header. See `docs/EVALUATION.md`, finding 1.

Full version details in [docs/LAB_INVENTORY.md](docs/LAB_INVENTORY.md).

## Components

| Component       | Version              | Function                                         | Deployed On  |
|-----------------|----------------------|--------------------------------------------------|--------------|
| Wazuh Manager   | v4.14.5              | Log ingestion, rule processing, alert generation | ubnsrv-aio   |
| Wazuh Indexer   | v4.14.5              | Alert storage and search (OpenSearch)            | ubnsrv-aio   |
| Wazuh Dashboard | v4.14.5              | Monitoring interface, investigation, reporting   | ubnsrv-aio   |
| Wazuh Agent     | v4.14.5              | Endpoint log collection and forwarding           | ubnsrv-agent |
| Wazuh Agent     | v4.14.5              | Endpoint log collection and forwarding           | winsrv-agent |
| Falco           | 0.43.1               | Runtime threat detection via eBPF                | ubnsrv-agent |
| auditd          | Ubuntu 22.04 package | Linux syscall auditing                           | ubnsrv-agent |
| Sysmon          | v15.20               | Windows process, network, and file telemetry     | winsrv-agent |

## Telemetry Sources and Log Flow

Three independent telemetry sources feed into the central Wazuh instance. Each uses a different collection mechanism.

**Linux endpoint:**

| Source | Collection                                   | Format | Transport              |
|--------|----------------------------------------------|--------|------------------------|
| auditd | localfile, /var/log/audit/audit.log         | audit  | Wazuh Agent, port 1514 |
| Falco  | localfile, /var/log/falco/falco_events.json | json   | Wazuh Agent, port 1514 |

**Windows endpoint:**

| Source          | Collection                                              | Format       | Transport              |
|-----------------|---------------------------------------------------------|--------------|------------------------|
| Sysmon          | eventchannel, Microsoft-Windows-Sysmon/Operational     | eventchannel | Wazuh Agent, port 1514 |
| PowerShell      | eventchannel, Microsoft-Windows-PowerShell/Operational | eventchannel | Wazuh Agent, port 1514 |
| Security Events | eventchannel, Security (filtered)                      | eventchannel | Wazuh Agent, port 1514 |

See [docs/LOG_FLOW.md](docs/LOG_FLOW.md) for detailed processing flow.

## Detection Engineering

### Custom Rules

Twenty custom Wazuh rules were developed to extend detection coverage beyond the built in ruleset, documented in [docs/CUSTOM_RULES.md](docs/CUSTOM_RULES.md).

The fifteen auditd rules carry a MITRE ATT&CK technique each. The four Falco rules and the
one SSH rule do not, because they route on Falco priority rather than on a behaviour, and
the technique is already carried in the Falco `tags` field of the event itself. See
`docs/EVALUATION.md`, finding 2.

One rule is inherited rather than written. Rule `100001` is the example rule shipped in the
stock `local_rules.xml`, matching `srcip` `1.1.1.1`, and it is kept only so the file stays
recognisable against the Wazuh default. It will not fire in this environment.

**Falco integration rules (117000-117003):**

| Rule ID | Condition             | Level | Trigger                                 |
|---------|-----------------------|-------|-----------------------------------------|
| 117000  | Any Falco JSON event  | 6     | Base rule                               |
| 117001  | Priority: Critical    | 10    | XZ backdoor, critical runtime events    |
| 117002  | Priority: Warning     | 7     | Sensitive file reads, account creation  |
| 117003  | Priority: Notice/Info | 5     | Network anomalies, informational events |

**auditd detection rules (210100-210114):**

| Rule ID | Audit Key                                          | Level | MITRE                                          |
|---------|----------------------------------------------------|-------|------------------------------------------------|
| 210100  | etcpasswd, shadow_access                           | 8     | T1003, OS Credential Dumping                  |
| 210101  | priv_esc                                           | 10    | T1548, Abuse Elevation Control                |
| 210102  | rootcmd                                            | 9     | T1548.003, Sudo and Sudo Caching              |
| 210103  | susp_activity                                      | 8     | T1059, Command and Scripting Interpreter      |
| 210104  | recon                                              | 6     | T1082, System Information Discovery           |
| 210105  | user_modification, group_modification              | 9     | T1136, Create Account                         |
| 210106  | sshd                                               | 10    | T1098, Account Manipulation                   |
| 210107  | remote_shell                                       | 12    | T1059.004, Unix Shell                         |
| 210108  | cron                                               | 8     | T1053.003, Cron                               |
| 210109  | modules                                            | 10    | T1547.006, Kernel Modules and Extensions      |
| 210110  | code_injection, data_injection, register_injection | 12    | T1055, Process Injection                      |
| 210111  | auditconfig, auditlog                              | 11    | T1070.002, Clear Linux or Mac System Logs     |
| 210112  | perm_mod                                           | 7     | T1222, File and Directory Permissions         |
| 210113  | T1011_Exfiltration_Over_Other_Network_Medium       | 10    | T1011, Exfiltration Over Other Network Medium |
| 210114  | T1081_Credentials_In_Files                         | 8     | T1552.001, Credentials In Files               |

The auditd ruleset in `configs/linux/auditd_rules.conf` defines 49 audit keys, and the 15
custom rules above act on 21 of them. Events carrying the other 28 keys still reach the
manager and still match the built in rule 80700 at level 0, so they are collected and
searchable but raise no alert. That is a deliberate position rather than an oversight, and
`docs/EVALUATION.md`, finding 4, lists which keys those are.

### Detection Coverage Summary

| Category                 | Source         | Coverage                                                                                   |
|--------------------------|----------------|--------------------------------------------------------------------------------------------|
| Runtime threat detection | Falco          | XZ backdoor patterns, sensitive file access, unexpected network activity, account creation |
| Credential access        | auditd         | /etc/shadow and /etc/passwd access monitoring                                              |
| Privilege escalation     | auditd         | sudo usage, SUID execution, root command tracking                                          |
| Persistence              | auditd         | Cron modification, kernel module loading                                                   |
| Defense evasion          | auditd         | Audit log and config tampering                                                             |
| Process injection        | auditd         | ptrace based injection (code, data, register)                                              |
| Lateral movement         | auditd         | SSH config modification                                                                    |
| Exfiltration             | auditd         | Raw socket creation monitoring                                                             |
| Windows process activity | Sysmon         | Full command line, hashes (MD5/SHA256/IMPHASH), parent process chain                       |
| PowerShell execution     | Sysmon         | Encoded commands, execution policy bypass, download cradles                                |
| Network connections      | Sysmon         | Outbound and inbound connection logging                                                    |
| Authentication failures  | Wazuh built in | SSH brute force, invalid user attempts                                                     |

## Validation Testing

All detection scenarios were tested and validated before production handover.

| Test Case                          | Endpoint     | Telemetry Source              | Rule Fired             | Result             |
|------------------------------------|--------------|-------------------------------|------------------------|--------------------|
| /etc/shadow access                 | ubnsrv-agent | auditd (key: etcpasswd)       | 210100, level 8, T1003 | Pass               |
| sudo whoami, sudo id               | ubnsrv-agent | auditd (key: recon + rootcmd) | 210104, 210102         | Pass               |
| curl, wget execution               | ubnsrv-agent | auditd (key: susp_activity)   | 210103, level 8        | Pass               |
| Falco, sensitive file read         | ubnsrv-agent | Falco                         | 117002, level 7        | Pass               |
| Falco, XZ backdoor pattern         | ubnsrv-agent | Falco                         | 117001, level 10       | Pass               |
| Sysmon process creation            | winsrv-agent | Sysmon Event ID 1             | Built in rules         | Pass               |
| PowerShell -ExecutionPolicy Bypass | winsrv-agent | Sysmon Event ID 1             | 92027, T1059.001       | Pass               |
| PowerShell -EncodedCommand         | winsrv-agent | Sysmon Event ID 1             | Built in rules         | Pass               |
| PowerShell IEX download cradle     | winsrv-agent | Sysmon Event ID 1 + 3         | Built in rules         | Pass               |
| Agent connectivity                 | Both         | Wazuh Manager                 | N/A                    | Pass, both Active |

Full test case documentation in [docs/DETECTION_TEST_CASES.md](docs/DETECTION_TEST_CASES.md).

---

## POC Dashboard

A custom security monitoring dashboard was built in Wazuh to consolidate all telemetry sources into a single operational view. The dashboard was used as the primary deliverable during the POC presentation.

Measured over the 24 hour window in `screenshots/Dashboard_Overview.png`:

| Counter              | Value  |
|----------------------|--------|
| Total alerts         | 50,626 |
| Falco alerts         | 8,034  |
| Sysmon alerts        | 7,956  |
| auditd alerts        | 1,712  |
| High severity alerts | 7,825  |

Total alert volume is dominated by authentication noise from the internet rather than by
the custom detections. The top triggered rule is the built in `sshd: Attempt to login using
a non existent user`, which is consistent with the brute force observation below.

Dashboard panels:
* Total alert counts by source (Sysmon, Falco, auditd, High Severity)
* Alert timeline (30-minute intervals, broken down by source)
* Total alert counter (24-hour window)
* Sysmon events table (Event ID, process, description)
* Falco alerts table (agent, rule, priority)
* Falco rule frequency chart
* Alerts by agent breakdown
* Recent alerts table with rule groups and descriptions
* auditd events table (agent, rule group, executable)
* Sysmon Event ID distribution
* Top triggered rules

Screenshots in `screenshots/`.

## Observations from Production Environment

During the POC and testing phase, the environment received real external attack traffic. Key observations:

* SSH brute force is continuous and high volume. The rule "sshd: Attempt to login using a non existent user" (Rule 5710) consistently ranks as the top triggered rule, with hundreds of attempts per hour from external IPs across multiple countries.
* Falco triggered a Critical alert, "Suspicious sshd Execution Pattern (XZ Backdoor
  Indicators)". It fires when sshd executes with the `EXE_WRITABLE` flag, which matches the
  behavioural signature of CVE-2024-3094, the XZ Utils supply chain backdoor. The Falco rule
  frequency panel shows it firing on the order of three thousand times in 24 hours, which is
  volume consistent with routine sshd behaviour on this build rather than with a compromise.
  It remains flagged for triage rather than closed.
* auditd rule 210113 dominates the auditd volume. It matches any process that opens a raw
  socket, and the dashboard breakdown shows that Falco is only part of it: the executables
  raising it include `/usr/bin/falco` at 393, `/usr/sbin/sshd` at 174, `/usr/lib/systemd/systemd`
  at 146, `/usr/bin/sudo` at 39, and `/usr/sbin/nginx` at 9, with a larger count from a local
  binary above all of them. An exclusion for `/usr/bin/falco` alone therefore removes under a
  quarter of the noise. See `docs/EVALUATION.md`, finding 11.

Sample alerts from the environment are in `sample_alerts/`.

## Known Issues and Planned Work

| Item                                                      | Priority | Notes                                        |
|-----------------------------------------------------------|----------|----------------------------------------------|
| Add exclusion for Falco in rule 210113                    | High     | Reduces FP noise from eBPF socket creation   |
| Triage XZ Backdoor Falco alert                            | High     | Determine true positive vs behavioral FP     |
| Create missing CDB lists (`common-ports`, `bash_profile`) | Medium   | Fixes silent skip of rules 102503 and 200120 |
| Implement multi record auditd correlation                 | Medium   | SYSCALL + PATH + EXECVE grouped context      |
| Add custom Sysmon rules for PowerShell abuse              | Low      | Currently relying on built in rules only     |
| Add network telemetry (Suricata or Zeek)                  | Low      | Future phase consideration                   |

## Repository Structure

```
.
├── README.md
├── LICENSE
├── docs/
│   ├── ARCHITECTURE.md              # two endpoint design, components, decisions
│   ├── WAZUH_SERVER_SETUP.md        # All in One installation on the manager host
│   ├── LINUX_AGENT_FALCO_AUDITD.md  # agent, Falco, and auditd on the Linux endpoint
│   ├── WINDOWS_AGENT_SYSMON.md      # agent and Sysmon on the Windows endpoint
│   ├── LOG_FLOW.md                  # how each telemetry source reaches an alert
│   ├── CUSTOM_RULES.md              # every custom rule, its logic and MITRE mapping
│   ├── DETECTION_TEST_CASES.md      # each test, the command run, and the result
│   ├── LAB_INVENTORY.md             # exact versions and command output per host
│   ├── EVALUATION.md                # audit of this repository against its own evidence
│   ├── TROUBLESHOOTING.md           # symptoms hit during the build and their fixes
│   └── LESSONS_LEARNED.md           # what would be done differently next time
├── configs/
│   ├── wazuh/                       # agent configuration for both endpoints
│   ├── linux/                       # auditd ruleset, Falco output and rule example
│   └── windows/                     # Sysmon configuration notes
├── rules/
│   └── local_rules.xml              # the 20 custom Wazuh rules
├── sample_alerts/                   # raw telemetry and the alerts it produced
├── diagrams/
│   └── architecture.mermaid         # the architecture diagram as a standalone file
└── screenshots/
```

Read `docs/ARCHITECTURE.md` first, then build in the order the setup documents are listed.
`docs/LOG_FLOW.md` explains what happens between an event on an endpoint and an alert on
the dashboard, `docs/CUSTOM_RULES.md` covers the detection logic, and `docs/EVALUATION.md`
records where this repository and its own evidence disagreed.

The three files in `sample_alerts/` are the same pipeline at two stages. The raw Falco and
auditd captures show what the endpoint produced, and the three alert files show what Wazuh
made of it.

## Screenshots

Captured from the running deployment, in `screenshots/`.

| File                       | What it shows                                                  |
|----------------------------|----------------------------------------------------------------|
| `Dashboard_Overview.png`   | the POC dashboard, all telemetry sources in one view           |
| `Agent_Overview.png`       | both agents active and reporting to the manager                |
| `Auditd_Overview.png`      | auditd alerts broken down by rule and executable               |
| `Falco_Overview.png`       | Falco alerts by rule and priority                              |
| `Sysmon_Overview.png`      | Sysmon events by Event ID and process                          |
| `Wazuh_Logtest_210100.png` | rule 210100 matching a captured audit event in `wazuh-logtest` |
| `Cover_Image.png`          | cover image used at the top of this page                       |

The `wazuh-logtest` capture carries more weight than the dashboard ones for anyone
verifying the work, because it shows a rule matching a specific input rather than a count
on a chart.

## Author

Dimasqi Ramadhani, Security Engineer

* [Portfolio](https://dimasqiramadhani.com)
* [GitHub](https://github.com/dimasqiramadhani)
* [LinkedIn](https://linkedin.com/in/dimasqiramadhani)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.