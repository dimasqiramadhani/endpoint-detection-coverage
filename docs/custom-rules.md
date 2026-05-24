# Custom Rules Documentation

Rules written for this implementation live in `/var/ossec/etc/rules/local_rules.xml` on `ubnsrv-aio`.
The file in this repo (`rules/local_rules.xml`) is the exact copy from the server.

---

## Rule ID Allocation

The lab uses these custom ID ranges:

| Range         | Purpose                               | Count |
|---------------|---------------------------------------|-------|
| 100001        | SSH example rule (original template)  | 1     |
| 117000–117003 | Falco integration rules               | 4     |
| 210100–210114 | auditd detection rules (MITRE-mapped) | 15    |

**Why 210100+?** The range 100100–200186 was already occupied by Sysmon MITRE rule files that were pre-installed on the Wazuh Manager (e.g. `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml`). When the auditd rules were first written using 100100–100116, Wazuh threw duplicate ID warnings and silently used only the Sysmon rules. Moving to 210100+ resolved this.

How to check available rule IDs before adding new ones:
```bash
grep -r "rule id=" /var/ossec/etc/rules/ | grep -v "if_sid" | awk -F'"' '{print $2}' | sort -n | tail -20
```

---

## Falco Rules (117000–117003)

### How Falco events reach Wazuh

```
Falco → /var/log/falco/falco_events.json (JSON, keep_alive: true)
       ↓
Wazuh Agent localfile (log_format: json)
       ↓
Wazuh Manager → built-in JSON decoder parses fields
       ↓
Rule 117000 matches: decoded_as=json + fields rule/priority/hostname present
       ↓
Child rules 117001-117003 match on priority field value
```

**No custom decoder needed.** Wazuh's built-in JSON decoder handles Falco output directly because Falco is configured to write JSON. The key fields that rule 117000 matches on (`rule`, `priority`, `hostname`) are top-level keys in Falco's JSON output.

### Rule design

Rule 117000 is intentionally broad - it matches any JSON event that has `rule`, `priority`, and `hostname` fields. In practice this means any Falco alert. The `$(rule)` and `$(output)` variables in the description pull directly from the Falco JSON fields, giving useful alert descriptions without needing field-specific rules for every Falco rule.

Child rules 117001–117003 only check the `priority` field to adjust the Wazuh level:

| Falco Priority         | Wazuh Rule    | Level |
|------------------------|---------------|-------|
| Critical               | 117001        | 10    |
| Warning                | 117002        | 7     |
| Notice / Informational | 117003        | 5     |
| Error (not matched)    | 117000 (base) | 6     |

> Note: Falco `Error` priority falls through to the base rule (117000, level 6). A separate child rule for Error could be added if needed.

### Verified detections

| Falco Rule                                                 | Priority | Wazuh Rule | Observed |
|------------------------------------------------------------|----------|------------|----------|
| Suspicious sshd Execution Pattern (XZ Backdoor Indicators) | Critical | 117001     | Yes      |
| Read sensitive file untrusted                              | Warning  | 117002     | Yes      |
| Unexpected UDP Traffic                                     | Notice   | 117003     | Yes      |
| Read ssh information                                       | Error    | 117000     | Yes      |
| Local Account Created via CLI                              | Warning  | 117002     | Yes      |

---

## auditd Rules (210100–210114)

### How auditd events reach Wazuh

```
auditd → /var/log/audit/audit.log (audit format)
       ↓
Wazuh Agent localfile (log_format: audit)
       ↓
Wazuh Manager → built-in auditd decoder parses SYSCALL/PATH/EXECVE records
       ↓
Rule 80700 matches: "Audit: Messages grouped" (level 0 - suppressed, not alerted)
       ↓
Child rules 210100-210114 match on audit.key field
       ↓
Alert generated at level 6–12 depending on rule
```

### Why rule 80700 matters

Rule 80700 is Wazuh's built-in catch-all for auditd events. It's level 0, meaning it never generates an alert by itself - it just groups auditd events for child rule processing. **All custom auditd rules must use `<if_sid>80700</if_sid>` as their parent.**

This is why the Dashboard showed 0 auditd alerts initially: the `audit.key` field values from the MITRE-mapped ruleset (e.g. `etcpasswd`, `rootcmd`, `susp_activity`) didn't match any existing child rules. Custom rules 210100–210114 were written to explicitly match these keys.

### Rule coverage

| Rule ID | Audit Key(s)                                             | Level | MITRE     | Description                  |
|---------|----------------------------------------------------------|-------|-----------|------------------------------|
| 210100  | `etcpasswd`, `shadow_access`                             | 8     | T1003     | Credential file accessed     |
| 210101  | `priv_esc`                                               | 10    | T1548     | Privilege escalation tool    |
| 210102  | `rootcmd`                                                | 9     | T1548.003 | Non-root user ran as root    |
| 210103  | `susp_activity`                                          | 8     | T1059     | Suspicious tool executed     |
| 210104  | `recon`                                                  | 6     | T1082     | Recon command executed       |
| 210105  | `user_modification`, `group_modification`                | 9     | T1136     | Account modified             |
| 210106  | `sshd`                                                   | 10    | T1098     | SSH config accessed/modified |
| 210107  | `remote_shell`                                           | 12    | T1059.004 | Possible reverse shell       |
| 210108  | `cron`                                                   | 8     | T1053.003 | Scheduled task modified      |
| 210109  | `modules`                                                | 10    | T1547.006 | Kernel module activity       |
| 210110  | `code_injection`, `data_injection`, `register_injection` | 12    | T1055     | Ptrace injection             |
| 210111  | `auditconfig`, `auditlog`, `T1005_...`                   | 11    | T1070.002 | Audit tamper                 |
| 210112  | `perm_mod`                                               | 7     | T1222     | File permission change       |
| 210113  | `T1011_Exfiltration_...`                                 | 10    | T1011     | Raw socket created           |
| 210114  | `T1081_Credentials_In_Files`                             | 8     | T1552.001 | Credential search tool       |

### Observed behavior

After deploying these rules, the implementation recorded 128+ auditd alerts in the first 24 hours. Top firing rules:
- **210113** (T1011, raw socket) - fires frequently because Falco itself creates raw sockets for eBPF monitoring. This is a false positive worth noting: the rule fires on legitimate Falco behavior.
- **210102** (rootcmd) - fires on any command run as root by a non-root user (via sudo/su).
- **210100** (etcpasswd) - fires when sshd, cron, and other daemons read `/etc/shadow` during normal authentication.

These observations are documented in `sample-alerts/` and `docs/lessons-learned.md`.

---

## Custom Decoders

No custom decoders were written for this implementation.

- **Falco**: handled by Wazuh's built-in JSON decoder. Falco JSON output is parsed automatically when `log_format: json` is set in the agent's `ossec.conf`.
- **auditd**: handled by Wazuh's built-in auditd decoder. The `log_format: audit` setting in the agent config activates this decoder.
- **Sysmon**: handled by Wazuh's built-in `windows_eventchannel` decoder.

`/var/ossec/etc/decoders/local_decoder.xml` contains only the default example decoder and has not been modified.

If Falco were configured to output plain text instead of JSON, a custom decoder would be needed to extract fields like `priority`, `rule`, and `output` from the text format. JSON output is strongly recommended to avoid this.

---

## Other Rule Files Present

The following custom rule files were pre-installed (not written by us):

```
100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml
101101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT2.xml
102101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT3.xml
106101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT7.xml
109101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT10.xml
110101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT11.xml
111101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT12.xml
112101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT13.xml
113101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT14.xml
114101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT15.xml
116101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT17.xml
117101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT18.xml
121101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT22.xml
121201-MITRE_TECHNIQUES_FROM_SYSMON_EVENT6.xml
200070-sysmon_reload.xml
200110-auditd.xml
```

These files provide MITRE ATT&CK-mapped rules for Sysmon event types and cover rule IDs 100100–200186. They are not included in this repo since they were pre-installed and are not part of this implementation's custom rules.
