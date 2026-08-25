# sample_alerts/

Sample alert data collected from this lab. All IPs have been redacted.

## Files

| File                                     | Source                                             | Description |
|------------------------------------------|----------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `alert_auditd_rule210113.json`           | Wazuh Dashboard (Discover)                         | auditd alert, Rule 210113, level 10, Raw socket created by Falco process (key: T1011_Exfiltration_Over_Other_Network_Medium). MITRE T1011.                                     |
| `alert_sshd_bruteforce_rule5710.json`    | Wazuh Dashboard (Discover)                         | SSH brute force alert, Rule 5710, level 5, Failed login for non existent user "guest" from UK IP. Includes GeoLocation, MITRE T1110.001.                                       |
| `alert_sysmon_powershell_rule92027.json` | Wazuh Dashboard (Discover)                         | Sysmon alert, Rule 92027, level 4, PowerShell spawning PowerShell with `-ExecutionPolicy Bypass`. Full hashes captured (MD5/SHA256/IMPHASH). MITRE T1059.001.                  |
| `falco_raw_alerts.jsonl`                 | `/var/log/falco/falco_events.json` on ubnsrv-agent | Raw Falco JSON output before Wazuh processing. Two alerts: Unexpected UDP Traffic (Notice) and XZ Backdoor Indicator (Critical).                                                 |
| `auditd_raw_events.txt`                  | `ausearch` output on ubnsrv-agent                  | Raw auditd events for three detection scenarios: /etc/shadow access (etcpasswd), root command execution (rootcmd), and curl execution (susp_activity). Includes field reference. |

The `.jsonl` file holds one JSON object per line and nothing else, so `jq` and any other
line oriented tool can read it directly. The commentary that used to sit inside it as `#`
lines is below, since `#` is not valid JSON and made the file unparseable.

## The Two Falco Alerts

**Unexpected UDP Traffic**, priority Notice. Routes to rule 117003 at level 5.

**Suspicious sshd Execution Pattern**, priority Critical, the highest priority observed in
this lab. Routes to rule 117001 at level 10. Falco raises it when sshd executes with the
`EXE_WRITABLE` flag, which is the behavioural signature of the XZ Utils supply chain
backdoor, CVE-2024-3094. It still needs triage to separate a true positive from normal
sshd daemon restart behaviour on this build.

## Notes

* `alert_auditd_rule210113.json` is interesting because it shows Falco itself triggering a Wazuh auditd rule, Falco creates raw sockets as part of normal operation (eBPF mode), which matches the T1011 audit rule. This is a false positive worth documenting.
* `alert_sshd_bruteforce_rule5710.json` shows real external attack traffic, not simulated, the lab received this from an address geolocated to the United Kingdom during normal operation.
* `alert_sysmon_powershell_rule92027.json` was triggered intentionally as part of detection testing. The full command line is captured by Sysmon Event ID 1.
* The XZ Backdoor Falco alert in `falco_raw_alerts.jsonl` is under investigation, `EXE_WRITABLE` flag on sshd could be a behavioral FP from normal sshd daemon restart behavior, not an actual compromise.
