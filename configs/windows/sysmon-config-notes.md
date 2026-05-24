# Sysmon Configuration - winsrv-agent (Windows Server 2019 Standard)

## Version

Sysmon v15.20 by Mark Russinovich and Thomas Garnier (Microsoft Sysinternals)
- Binary: `C:\Windows\Sysmon64.exe`
- Driver: `SysmonDrv.sys` (installed 2026-03-26)
- Config last updated: 2026-05-09

## Config File

```
Config file : C:\Sysmon\sysmonconfig.xml
Config hash : SHA256=055FEBC600E6D7448CF38123072759129 27A62B1F94D0D933B64B294BC87162
```

The config file is stored at `C:\Sysmon\sysmonconfig.xml`. The hash above can
be used to identify the exact config version if needed.

## Hashing Algorithms

Sysmon is configured to capture: **MD5, SHA256, IMPHASH**

Confirmed from PowerShell detection alert:
```
Hashes: MD5=7353F60B1739074EB17C5F4DDDEFE239
        SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C
        IMPHASH=741776AACCFC5B71FF59832DCDCACE0F
```

## Network Connection Monitoring

Network connection logging is **enabled** (`sysmon64.exe -c` confirmed).

Real inbound RDP connection detected (Event ID 3):
- Source: external IP (redacted)
- Destination: winsrv-agn:3389
- Process: svchost.exe (NT AUTHORITY\NETWORK SERVICE)

## Wazuh Agent - Event Channel Config

```xml
<!-- Sysmon events -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- PowerShell script block logging -->
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

## Sysmon Event IDs Active in This Lab

| Event ID | Description        | Status                                        |
|----------|--------------------|-----------------------------------------------|
| 1        | Process creation   | Confirmed - PowerShell detection (Rule 92027) |
| 3        | Network connection | Confirmed - RDP inbound, IEX download cradle  |
| 11       | File created       | Confirmed - cleanmgr.exe and others           |
| 13       | Registry value set | Active                                        |
| 22       | DNS query          | Active                                        |

## Confirmed Detection Example

PowerShell `-ExecutionPolicy Bypass` → Wazuh Rule 92027:
- MITRE: T1059.001 (Execution tactic)
- Command line: `powershell.exe -ExecutionPolicy Bypass -Command "Write-Host 'detection-test'"`
- Parent: PowerShell spawning PowerShell
- Integrity level: High
- Hashes: MD5 + SHA256 + IMPHASH all captured

## Install / Update Commands

```powershell
# Install with config
sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml

# Update config without reinstall
sysmon64.exe -c C:\Sysmon\sysmonconfig.xml

# Check current config and version
sysmon64.exe -c

# Verify service running
Get-Service Sysmon64
```
