# Lab Inventory & Version Reference

Collected: 2026-05-25
Environment: 3-VM lab (all VMs running on cloud/hosted infrastructure)

---

## Wazuh Manager: ubnsrv-aio

**Agent list output (`manage_agents -l`):**
```
Available agents:
   ID: 001, Name: ubnsrv-agent, IP: any
   ID: 002, Name: winsrv-agent, IP: any
```

**Agent status output (`agent_control -lc`):**
```
Wazuh agent_control. List of available agents:
   ID: 000, Name: ubnsrv-aio (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: ubnsrv-agent, IP: any, Active
   ID: 002, Name: winsrv-agent, IP: any, Active
```

**Wazuh version (`wazuh-control info`):**
```
WAZUH_VERSION="v4.14.5"
WAZUH_REVISION="rc1"
WAZUH_TYPE="server"
```

---

## Linux Endpoint: ubnsrv-agent

**OS:**
```
NAME="Ubuntu"
VERSION="22.04.5 LTS (Jammy Jellyfish)"
```

**Kernel:**
```
Linux ubnsrv-falco 5.15.0-179-generic #189-Ubuntu SMP Tue May 5 18:20:56 UTC 2026 x86_64
```

**Wazuh Agent version:**
```
WAZUH_VERSION="v4.14.5"
WAZUH_REVISION="rc1"
WAZUH_TYPE="agent"
```

**Falco version:**
```
Falco version: 0.43.1 (x86_64)
Engine version: 0.58.0 (engine_version: 58)
Libs version: 0.23.2
Plugin API version: 3.12.0
Driver API version: 8.0.0
Driver schema version: 4.1.0
Default driver version: 9.1.0+driver
```

Falco config files loaded:
* `/etc/falco/config.d/engine-kind-falcoctl.yaml`
* `/etc/falco/config.d/falco.container_plugin.yaml`
* `/etc/falco/falco.yaml`

Custom rules in `/etc/falco/rules.d/`:
* `falco-incubating_rules.yaml`
* `falco-linux-enchance.yaml`

**auditd:**
```
Version: part of linux-audit package (Ubuntu 22.04)
Service: active (running) since 2026-05-18
```
> Note: `auditd --version` flag not supported on this version. Version info tied to the `auditd` package from Ubuntu 22.04 repos.

**Audit rules:** 200+ rules loaded (MITRE ATT&CK mapped). See `configs/linux/auditd_rules.conf`.

---

## Windows Endpoint: winsrv-agent

**OS:**
```
OsName        : Microsoft Windows Server 2019 Standard
OsVersion     : 10.0.17763
OsBuildNumber : 17763
CsName        : WINSRV-AGN
```

**Wazuh Agent version:** v4.14.5
> Registry path `HKLM:\SOFTWARE\WOW6432Node\ossec` not found, so the agent may be installed
> under 64-bit path. Version confirmed from Dashboard agent inventory (v4.14.5).

**Sysmon:**
```
System Monitor v15.20 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2026 Microsoft Corporation

Config file  : C:\Sysmon\sysmonconfig.xml
Config hash  : SHA256=055FEBC600E6D7448CF381230727591292 7A62B1F94D0D933B64B294BC87162
Hashing      : MD5, SHA256, IMPHASH
Network conn : enabled
```

**PowerShell:**
```
PSVersion : 5.1.17763.6532
OS        : Microsoft Windows 10.0.17763
```

---

## Summary Table

| Component       | Host         | Version                             |
|-----------------|--------------|-------------------------------------|
| Wazuh Manager   | ubnsrv-aio   | v4.14.5 (rc1)                       |
| Wazuh Indexer   | ubnsrv-aio   | v4.14.5                             |
| Wazuh Dashboard | ubnsrv-aio   | v4.14.5                             |
| Wazuh Agent     | ubnsrv-agent | v4.14.5 (rc1)                       |
| Wazuh Agent     | winsrv-agent | v4.14.5                             |
| Ubuntu          | ubnsrv-agent | 22.04.5 LTS (Jammy Jellyfish)       |
| Kernel          | ubnsrv-agent | 5.15.0-179-generic                  |
| Falco           | ubnsrv-agent | 0.43.1 (libs 0.23.2, engine 0.58.0) |
| auditd          | ubnsrv-agent | Ubuntu 22.04 package                |
| Windows Server  | winsrv-agent | 2019 Standard (Build 17763)         |
| Sysmon          | winsrv-agent | v15.20                              |
| PowerShell      | winsrv-agent | 5.1.17763.6532                      |
