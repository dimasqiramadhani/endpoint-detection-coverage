# Detection Test Cases

Validation testing conducted to confirm detection coverage before production handover. All test cases were run in the cloned pre production environment.

---

## TC-01: Sensitive File Access via auditd

**Objective:** Confirm that access to /etc/shadow and /etc/passwd is captured by auditd and generates a Wazuh alert.

**Source:** auditd (key: etcpasswd) -> Wazuh Agent -> Rule 210100

**Test command:**
```bash
cat /etc/shadow
```

**Expected auditd event:**
```
type=SYSCALL ... comm="cat" exe="/usr/bin/cat" key="etcpasswd"
```

**Expected Wazuh alert:**
* Rule: 210100
* Level: 8
* Description: "Auditd: Sensitive credential file accessed (/usr/bin/cat by uid=0)"
* MITRE: T1003

**Result:** Pass. Rule 210100 fired. Alert visible in Dashboard under rule.groups: auditd.

**Sample alert:** `sample_alerts/alert_auditd_rule210113.json` (same auditd pipeline, different key)

---

## TC-02: Privilege Escalation via auditd

**Objective:** Confirm that sudo and su usage is captured under both the recon and rootcmd audit keys.

**Source:** auditd (keys: recon, rootcmd) -> Wazuh Agent -> Rules 210104, 210102

**Test commands:**
```bash
sudo whoami
sudo id
```

**Expected Wazuh alerts:**
* Rule 210104, level 6 (recon key, since whoami and id are in the recon watch list)
* Rule 210102, level 9 (rootcmd key, a non root user running a command with euid=0)

**Result:** Pass. Both rules fired on the same command execution.

---

## TC-03: Suspicious Tool Execution via auditd

**Objective:** Confirm that execution of tools in the susp_activity watch list is captured.

**Source:** auditd (key: susp_activity) -> Wazuh Agent -> Rule 210103

**Test commands:**
```bash
curl --version
wget --version
```

**Expected Wazuh alert:**
* Rule: 210103
* Level: 8
* MITRE: T1059

**Result:** Pass.

**Raw auditd event from ausearch:**
```
type=SYSCALL ... comm="curl" exe="/usr/bin/curl" key="susp_activity"
```

---

## TC-04: Falco: Sensitive File Read

**Objective:** Confirm that Falco detects and reports sensitive file reads, and the alert reaches Wazuh.

**Source:** Falco -> /var/log/falco/falco_events.json -> Wazuh Agent -> Rule 117002

**Test command:**
```bash
cat /etc/shadow
```

**Expected Falco alert (raw JSON):**
```json
{
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "hostname": "ubnsrv-falco"
}
```

**Expected Wazuh alert:**
* Rule: 117002
* Level: 7
* Description: "Falco Warning: Read sensitive file untrusted"

**Result:** Pass. Alert visible in Dashboard under rule.groups: falco.

---

## TC-05: Falco: XZ Backdoor Pattern

**Objective:** Confirm that Falco's XZ backdoor detection rule fires and the alert reaches Wazuh at Critical priority.

**Source:** Falco -> Wazuh Agent -> Rule 117001

**Trigger:** sshd executing with EXE_WRITABLE flag (occurs during normal sshd daemon restart in this environment)

**Expected Falco alert:**
```json
{
  "priority": "Critical",
  "rule": "Suspicious sshd Execution Pattern (XZ Backdoor Indicators)",
  "output_fields": {
    "evt.arg.flags": "EXE_WRITABLE",
    "proc.name": "sshd"
  }
}
```

**Expected Wazuh alert:**
* Rule: 117001
* Level: 10
* Description: "Falco Critical: Suspicious sshd Execution Pattern (XZ Backdoor Indicators)"

**Result:** Pass. Note: this alert requires triage. EXE_WRITABLE on sshd may indicate a true positive (XZ backdoor) or a false positive from normal sshd restart behavior (daemon runs again itself). See known issues.

**Raw Falco alert:** `sample_alerts/falco_raw_alerts.jsonl`

---

## TC-06: Sysmon: Process Creation

**Objective:** Confirm that Sysmon Event ID 1 is collected by the Wazuh Agent and appears in the Dashboard with full telemetry.

**Source:** Sysmon Event ID 1 -> Windows Event Log -> Wazuh Agent -> built in rules

**Test command (on winsrv-agent):**
```powershell
cmd.exe /c whoami
```

**Expected telemetry in Wazuh:**
* data.win.system.eventID: 1
* data.win.eventdata.commandLine: populated
* data.win.eventdata.hashes: MD5, SHA256, IMPHASH
* data.win.eventdata.parentImage: populated
* data.win.eventdata.user: populated

**Result:** Pass. Events appearing in Discover with full field population.

---

## TC-07: Sysmon: PowerShell Execution Policy Bypass

**Objective:** Confirm that PowerShell with -ExecutionPolicy Bypass is captured by Sysmon and triggers a Wazuh detection rule.

**Source:** Sysmon Event ID 1 -> Wazuh Agent -> Rule 92027

**Test command (on winsrv-agent):**
```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Write-Host 'detection-test'"
```

**Expected Wazuh alert:**
* Rule: 92027
* Level: 4
* Description: "Powershell process spawned powershell instance"
* MITRE: T1059.001

**Result:** Pass. Full command line captured including `-ExecutionPolicy Bypass`. Hashes: MD5=7353F60B..., SHA256=DE96A6E6..., IMPHASH=74177...

**Sample alert:** `sample_alerts/alert_sysmon_powershell_rule92027.json`

---

## TC-08: Sysmon: Encoded PowerShell Command

**Objective:** Confirm that PowerShell with -EncodedCommand is captured by Sysmon.

**Source:** Sysmon Event ID 1 -> Wazuh Agent

**Test command (on winsrv-agent):**
```powershell
# Encodes "whoami"
powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA
```

**Expected telemetry:**
* commandLine field contains `-EncodedCommand`
* Parent and child process chain captured

**Result:** Pass. Event captured in Discover.

---

## TC-09: Sysmon: PowerShell Download Cradle (IEX)

**Objective:** Confirm that PowerShell IEX download cradle triggers both a process creation event (Event ID 1) and a network connection event (Event ID 3).

**Source:** Sysmon Event ID 1 + 3 -> Wazuh Agent

**Test command (on winsrv-agent):**
```powershell
# Points to localhost, connection will fail - that is expected
powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/test')"
```

**Expected telemetry:**
* Event ID 1: process creation with full command line
* Event ID 3: network connection attempt to 127.0.0.1:80

**Result:** Pass. Both event types captured. Connection failure (404) is expected behavior.

---

## TC-10: Agent Connectivity Validation

**Objective:** Confirm both agents are connected and Active on the Manager.

**Source:** Wazuh Manager

**Verification:**
```bash
sudo /var/ossec/bin/agent_control -lc
```

**Expected output:**
```
ID: 000, Name: ubnsrv-aio (server), IP: 127.0.0.1, Active/Local
ID: 001, Name: ubnsrv-agent, IP: any, Active
ID: 002, Name: winsrv-agent, IP: any, Active
```

**Result:** Pass. Both agents Active throughout the engagement.
