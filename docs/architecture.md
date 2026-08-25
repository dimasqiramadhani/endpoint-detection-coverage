# Architecture

## Overview

The implementation uses three servers deployed in a cloned environment prior to production rollout. All components communicate over an internal network. Agent to Manager traffic is encrypted over port 1514.

## Components

### Wazuh All in One (ubnsrv-aio)

Runs all three Wazuh components on a single server (Wazuh v4.14.5):

* **Wazuh Manager** (port 1514/1515): Receives agent data, processes detection rules, generates alerts. Cluster node: node01.
* **Wazuh Indexer** (port 9200): OpenSearch based storage. Index pattern: wazuh-alerts-*.
* **Wazuh Dashboard** (port 443): Web interface for alert monitoring, investigation, and reporting. A custom security monitoring dashboard was built for POC presentation and ongoing operations.

### Linux Server Endpoint (ubnsrv-agent, Agent 001)

Ubuntu 22.04.5 LTS, running three telemetry sources:

* **Wazuh Agent v4.14.5**: Collects local logs and forwards to the Manager. Groups: default, Linux.
* **Falco 0.43.1**: Runtime threat detection via eBPF. Monitors system calls and writes alerts in JSON format to `/var/log/falco/falco_events.json`. The Wazuh Agent reads this file and forwards to the Manager.
* **auditd**: Linux kernel audit daemon. Captures syscall level events based on a MITRE ATT&CK mapped ruleset. Logs written to `/var/log/audit/audit.log`, read by the Wazuh Agent.

### Windows Server Endpoint (winsrv-agent, Agent 002)

Windows Server 2019 Standard (Build 10.0.17763), running:

* **Wazuh Agent v4.14.5**: Collects Windows Event Log channels and forwards to the Manager. Groups: default, Windows.
* **Sysmon v15.20**: Provides detailed process, network, file, and registry telemetry via the Windows Event Log. Config file at `C:\Sysmon\sysmonconfig.xml`. Hashing enabled: MD5, SHA256, IMPHASH.

## Network

```
[ubnsrv-agent] --(port 1514, TLS)--> [ubnsrv-aio / Wazuh Manager]
[winsrv-agent] --(port 1514, TLS)--> [ubnsrv-aio / Wazuh Manager]

Dashboard: https://<manager-ip>:443
```

Internal IPs are redacted in this repository.

## Design Decisions

**All in One deployment:** Selected for the initial implementation scope. A distributed architecture (separate Manager, Indexer, Dashboard nodes) would be appropriate for higher volume or multi site deployments. This can be revisited in a future phase.

**Falco on Linux, Sysmon on Windows:** Falco is Linux native and provides eBPF based runtime monitoring without a separate kernel module in newer deployments. Sysmon fills the equivalent role on Windows with comparable telemetry depth.

**Falco JSON output:** Configured to output JSON rather than plain text. This allows Wazuh's built in JSON decoder to parse Falco events without a custom decoder, reducing maintenance overhead.

**MITRE ATT&CK mapped auditd ruleset:** The auditd rules use audit keys that follow MITRE technique naming conventions (e.g. `T1011_Exfiltration_Over_Other_Network_Medium`). This makes it straightforward to map auditd events to MITRE techniques in Wazuh custom rules.

**Custom Wazuh rules:** Wazuh's built in auditd rule 80700 suppresses all audit events at level 0. Custom child rules (210100-210114) were written to match specific audit keys and generate actionable alerts. See [CUSTOM_RULES.md](CUSTOM_RULES.md).
