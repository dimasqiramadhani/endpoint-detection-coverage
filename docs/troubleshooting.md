# Troubleshooting Notes

Issues encountered during implementation and testing, with resolution steps.

---

## auditd Producing No Alerts

**Symptom:** auditd service running, audit rules loaded, events visible in `ausearch` and in raw Discover results, but zero alerts in Security Events or the custom dashboard widget.

**Root cause:** Wazuh's built-in rule 80700 ("Audit: Messages grouped") matches all auditd events at level 0. Level 0 events are indexed but never generate alerts. The rule exists as a parent for child rules that should override it with higher levels, but none of the default child rules matched the audit key values from the MITRE-mapped auditd ruleset in use.

**Resolution:** Wrote custom rules 210100-210114 in `local_rules.xml` using `<if_sid>80700</if_sid>` as the parent, matching the specific audit key values (`etcpasswd`, `rootcmd`, `susp_activity`, etc.). Restarted the Manager and verified with `wazuh-logtest`:

```
**Phase 3: Completed filtering (rules).
    id: '210100'
    level: '8'
    description: 'Auditd: Sensitive credential file accessed...'
**Alert to be generated.
```

**Verification command:**
```bash
sudo /var/ossec/bin/wazuh-logtest
# Paste a SYSCALL line from /var/log/audit/audit.log
# Confirm Phase 3 shows the custom rule ID, not 80700
```

---

## Custom Rule ID Conflicts

**Symptom:** `wazuh-logtest` outputs duplicate rule ID warnings for every custom rule. The intended rules are silently ignored in favor of the first definition loaded.

**Root cause:** Pre-installed Sysmon MITRE rule files occupied IDs 100100-200186. The initial custom auditd rules were assigned IDs in the same range.

**Resolution:** Checked the full rule ID space and moved custom rules to 210100+.

```bash
# Check highest rule ID in use
grep -r "rule id=" /var/ossec/etc/rules/ | grep -v "if_sid" | awk -F'"' '{print $2}' | sort -n | tail -20
```

**Prevention:** Run this check before assigning any new rule IDs.

---

## Missing CDB Lists (Open)

**Symptom:** Warning on every Manager restart:
```
List 'etc/lists/common-ports' could not be loaded. Rule '102503' will be ignored.
List 'etc/lists/bash_profile' could not be loaded. Rule '200120' will be ignored.
```

**Root cause:** Rules 102503 and 200120 reference CDB lookup files that are not present in `/var/ossec/etc/lists/`. The directory contains only: `amazon`, `audit-keys`, `malicious-ioc`, `security-eventchannel`.

**Status:** Open. Rules 102503 and 200120 are skipped on every restart. No impact on current detection coverage. Planned fix: create the missing CDB files or remove the rules referencing them.

---

## Sysmon Events Not Appearing in Dashboard

**Symptom:** Wazuh Agent connected and Active on Windows endpoint, but Sysmon events not visible in Discover or Security Events.

**Root cause:** The agent `ossec.conf` was missing the `localfile` entry for the Sysmon event channel. Adding the entry and using the wrong `log_format` value (`eventlog` instead of `eventchannel`) would also silently drop events.

**Resolution:** Added to agent `ossec.conf`:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restarted the Wazuh Agent service and confirmed events appeared in Discover within a few minutes.

**Note:** The PowerShell Operational channel was added at the same time:
```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

---

## Verifying Agent Connectivity

```bash
# On the Manager
sudo /var/ossec/bin/agent_control -lc

# Expected output
ID: 000, Name: ubnsrv-aio (server), IP: 127.0.0.1, Active/Local
ID: 001, Name: ubnsrv-agent, IP: any, Active
ID: 002, Name: winsrv-agent, IP: any, Active
```

If an agent shows Disconnected, check:
1. Firewall on the Manager - port 1514 TCP must be open inbound
2. Agent config - `<address>` in `ossec.conf` must match the Manager IP
3. Agent service status: `systemctl status wazuh-agent` (Linux) or `Get-Service WazuhSvc` (Windows)
4. Agent logs: `/var/ossec/logs/ossec.log`

---

## General Debugging Reference

```bash
# Test a raw log line against Wazuh rules (run on Manager)
sudo /var/ossec/bin/wazuh-logtest

# Check Manager logs for errors
sudo tail -f /var/ossec/logs/ossec.log

# Verify rule file syntax (look for errors in Manager log after restart)
sudo systemctl restart wazuh-manager
sudo grep -i "error\|invalid\|failed" /var/ossec/logs/ossec.log | tail -20

# Check which rules are loaded for a given ID
grep -r "rule id=\"80700\"" /var/ossec/ruleset/rules/
```
