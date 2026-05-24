# sample-alerts/

Sample alert data collected from this lab. All IPs have been redacted.

## Files

| File                                     | Source                                             | Description |
|------------------------------------------|----------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `alert-auditd-rule210113.json`           | Wazuh Dashboard (Discover)                         | auditd alert - Rule 210113, level 10 - Raw socket created by Falco process (key: T1011_Exfiltration_Over_Other_Network_Medium). MITRE T1011.                                     |
| `alert-sshd-bruteforce-rule5710.json`    | Wazuh Dashboard (Discover)                         | SSH brute-force alert - Rule 5710, level 5 - Failed login for non-existent user "guest" from UK IP. Includes GeoLocation, MITRE T1110.001.                                       |
| `alert-sysmon-powershell-rule92027.json` | Wazuh Dashboard (Discover)                         | Sysmon alert - Rule 92027, level 4 - PowerShell spawning PowerShell with `-ExecutionPolicy Bypass`. Full hashes captured (MD5/SHA256/IMPHASH). MITRE T1059.001.                  |
| `falco-raw-alerts.jsonl`                 | `/var/log/falco/falco_events.json` on ubnsrv-agent | Raw Falco JSON output before Wazuh processing. Two alerts: Unexpected UDP Traffic (Notice) and XZ Backdoor Indicator (Critical).                                                 |
| `auditd-raw-events.txt`                  | `ausearch` output on ubnsrv-agent                  | Raw auditd events for three detection scenarios: /etc/shadow access (etcpasswd), root command execution (rootcmd), and curl execution (susp_activity). Includes field reference. |

## Notes

- `alert-auditd-rule210113.json` is interesting because it shows Falco itself triggering a Wazuh auditd rule - Falco creates raw sockets as part of normal operation (eBPF mode), which matches the T1011 audit rule. This is a false positive worth documenting.
- `alert-sshd-bruteforce-rule5710.json` shows real external attack traffic, not simulated - the lab received this from a UK-based IP during normal operation.
- `alert-sysmon-powershell-rule92027.json` was triggered intentionally as part of detection testing. The full command line is captured by Sysmon Event ID 1.
- The XZ Backdoor Falco alert in `falco-raw-alerts.jsonl` is under investigation - `EXE_WRITABLE` flag on sshd could be a behavioral FP from normal sshd daemon restart behavior, not an actual compromise.
