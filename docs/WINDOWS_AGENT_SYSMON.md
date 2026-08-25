# Windows Agent Setup: Sysmon (winsrv-agent)

## Overview

winsrv-agent is a Windows Server 2019 Standard (Build 10.0.17763) running:
* Wazuh Agent v4.14.5 (log forwarding)
* Sysmon v15.20 (process, network, file, registry, DNS telemetry)

## Wazuh Agent

### Version

v4.14.5, installed on Windows Server 2019 Standard.

### Installation

```powershell
# Silent install
wazuh-agent-4.14.5-1.msi /q WAZUH_MANAGER="<manager-ip>"

# Verify service
Get-Service WazuhSvc
```

### Verify Connection

On the Manager:
```bash
sudo /var/ossec/bin/agent_control -lc
# ID: 002, Name: winsrv-agent, IP: any, Active
```

## Sysmon

### Version

```
System Monitor v15.20
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2026 Microsoft Corporation
```

Binary location: `C:\Windows\Sysmon64.exe`
Driver: `SysmonDrv.sys` (installed 2026-03-26)

### Configuration

Config file: `C:\Sysmon\sysmonconfig.xml`
Config SHA256: `055FEBC600E6D7448CF38123072759129 27A62B1F94D0D933B64B294BC87162`

Hashing algorithms enabled: **MD5, SHA256, IMPHASH**
Network connection logging: **enabled**

### Installation

```powershell
# Install with config
sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml

# Update config without reinstalling
sysmon64.exe -c C:\Sysmon\sysmonconfig.xml

# Verify active config
sysmon64.exe -c

# Verify service
Get-Service Sysmon64
```

### Event IDs Active in This Implementation

| Event ID | Description         | Status                                              |
|----------|---------------------|-----------------------------------------------------|
| 1        | Process creation    | Active, confirmed PowerShell detection             |
| 3        | Network connection  | Active, confirmed RDP inbound, IEX download cradle |
| 6        | Driver loaded       | Active                                              |
| 7        | Image loaded        | Active                                              |
| 10       | Process access      | Active                                              |
| 11       | File created        | Active                                              |
| 12/13/14 | Registry events     | Active                                              |
| 15       | File stream created | Active                                              |
| 17/18    | Pipe events         | Active                                              |
| 22       | DNS query           | Active                                              |

### Confirmed Detection

PowerShell `-ExecutionPolicy Bypass` captured by Sysmon Event ID 1, matched by Wazuh Rule 92027 (MITRE T1059.001):

```
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -Command "Write-Host 'detection-test'"
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
IntegrityLevel: High
Hashes: MD5=7353F60B..., SHA256=DE96A6E6..., IMPHASH=74177...
```

## Wazuh Agent: Event Channel Configuration

From `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<ossec_config>

  <client>
    <server>
      <address>MANAGER_IP</address>
    </server>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
  </client_buffer>

  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and
      EventID != 4656 and EventID != 4658 and EventID != 4663 and EventID != 4660 and
      EventID != 4670 and EventID != 4690 and EventID != 4703 and EventID != 4907 and
      EventID != 5152 and EventID != 5157]</query>
  </localfile>

  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

</ossec_config>
```

### Important Notes

* `log_format` must be `eventchannel`, not `eventlog`. Using `eventlog` silently drops events with no error message.
* The Security channel query filters high volume noise events (object access, policy changes) that are not relevant to detection.
* Restart the Wazuh Agent after any `ossec.conf` change: `Restart-Service WazuhSvc`

## Verify Events in Wazuh

```powershell
# Generate a test process creation event
powershell.exe -ExecutionPolicy Bypass -Command "Write-Host 'test'"
```

In Wazuh Dashboard, filter by:
* agent.name: winsrv-agent
* data.win.system.channel: Microsoft-Windows-Sysmon/Operational
* data.win.system.eventID: 1
