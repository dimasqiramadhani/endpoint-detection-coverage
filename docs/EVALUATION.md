# Evaluation

Every document in this repository was checked against the configuration it describes, the rules were checked against the auditd ruleset that feeds them, and both were checked against the captured alerts and screenshots.

Three sources of truth were used and they rank in this order. The **sample alerts and screenshots** are what the running deployment produced. The **rule file and the configurations** are what was deployed. The **documents** describe both. Where a document disagreed with a configuration, the document was corrected. Where a configuration disagreed with the evidence, the evidence won.

## What Was Checked

| Check                                  | Method                                                                                              | Result                                            |
|----------------------------------------|-----------------------------------------------------------------------------------------------------|---------------------------------------------------|
| Hostname consistency                   | every hostname in every file, against the agent field and the raw log headers in the samples        | 2 naming layers, both real, now documented        |
| Rule inventory                         | every rule ID, level, and MITRE tag in the XML against both tables that list them                   | consistent, 20 rules                              |
| MITRE coverage claim                   | the README claim against the rule file                                                              | 5 of 20 rules carry no technique, claim corrected |
| Audit key wiring                       | every key referenced by a rule against every key defined in the auditd ruleset                      | no orphan rules, 28 keys with no rule             |
| Telemetry paths                        | the Falco output path and the agent localfile paths                                                 | consistent                                        |
| Versions                               | every version string in documents and configurations                                                | consistent throughout                             |
| Cross references                       | every file path mentioned in a document                                                             | 1 broken link, corrected                          |
| Redaction                              | the whole repository                                                                                | 2 redaction styles, unified                       |
| Duplicate diagrams                     | all three copies of the architecture, in the README, the standalone file, and the log flow document | 2 diverged, now consistent                        |
| Reported volumes against the dashboard | every alert count in every file against the dashboard capture                                       | 2 stale counts, corrected from the screenshot     |
| Telemetry paths against the evidence   | the Falco path in every file against the Falco configuration                                        | 1 document wrong, corrected                       |
| Empty scaffolding                      | every file and folder against its content                                                           | 7 placeholder files, removed                      |

## Finding 1: The Endpoints Carry Two Names, and Both Are Real

The environment inventory lists the two endpoints as `ubnsrv-agent` and `winsrv-agent`. The evidence shows different names in the same deployment.

| Evidence                             | Field                         | Name                           |
|--------------------------------------|-------------------------------|--------------------------------|
| all three sample alerts              | `agent.name`                  | `ubnsrv-agent`, `winsrv-agent` |
| SSH brute force sample               | `predecoder.hostname`         | `ubnsrv-falco`                 |
| `uname -a` in the inventory document | operating system hostname     | `ubnsrv-falco`                 |
| Sysmon PowerShell sample             | `data.win.system.computer`    | `winsrv-agn`                   |
| Falco raw capture                    | `hostname` and `evt.hostname` | `ubnsrv-falco`                 |

Neither name is wrong. Wazuh takes the agent name from enrollment, so it can differ from what the machine calls itself, and on this Linux host it does.

The consequence is practical. Alerts are attributed by `agent.name`, so filtering a dashboard by `ubnsrv-falco` returns only events that carry a raw log header, such as sshd messages and Falco output, and silently misses everything decoded from auditd. Anyone correlating these alerts against a CMDB or any other source keyed on hostname has to carry the mapping.

Recorded rather than renamed. Renaming an enrolled agent means re enrolling it, and the agent IDs, test results, and sample alerts throughout this repository are written against the current names.

## Finding 2: Not All Rules Are MITRE Mapped

The README stated that all rules are MITRE ATT&CK mapped. Fifteen are. Five are not.

| Rules                                  | MITRE tag                    |
|----------------------------------------|------------------------------|
| 210100 to 210114, the auditd rules     | one technique each, 15 of 15 |
| 117000 to 117003, the Falco rules      | none                         |
| 100001, the inherited SSH example rule | none                         |

The gap is defensible for the Falco rules. They route on the Falco `priority` field rather than on a behaviour, so a single technique would be wrong on most events they match, and the Falco event already carries its own `tags` array with the technique in it. The captured XZ backdoor alert, for example, carries `T1021.004` from Falco itself.

The claim was the problem, not the rules. The README now says which rules carry a technique and why the others do not. Worth considering for a later pass: mapping the technique out of the Falco `tags` field into the Wazuh alert would make both consistent without inventing an attribution.

## Finding 3: One Rule Is Inherited From the Wazuh Template

Rule `100001` matches `srcip` `1.1.1.1` and describes it as an sshd authentication failure. That is the example rule shipped in the stock `local_rules.xml`, unchanged.

It will not fire in this environment, and it was never mentioned in the README while the other nineteen were. It is now disclosed as inherited rather than written. Keeping it is reasonable, since it makes the file recognisable against the Wazuh default, but presenting nineteen written rules as twenty is not.

## Finding 4: Twenty Eight Audit Keys Raise No Alert

The auditd ruleset defines 49 keys. The custom rules act on 21 of them. Every key a rule references is produced by the configuration, so there are no orphan rules, but the reverse is not true.

Events carrying these 28 keys reach the manager, match the built in rule 80700 at level 0, and are stored without ever raising an alert:

* `KEXEC`
* `T1002_Data_Compressed`
* `actions`
* `audispconfig`
* `audittools`
* `etcgroup`
* `filebeat`
* `localtime`
* `locklvm`
* `login`
* `modprobe`
* `mount`
* `network`
* `network_connect_4`
* `network_connect_6`
* `network_modifications`
* `opasswd`
* `pam`
* `passwd_access`
* `passwd_modification`
* `power`
* `rootkey`
* `session`
* `sharedmemaccess`
* `specialfiles`
* `swap`
* `sysctl`
* `systemd`

Some of that is deliberate. `filebeat`, `session`, and `login` are high volume and low value on their own. Others are gaps worth closing, and `passwd_modification`, `opasswd`, and `pam` stand out, since credential and authentication changes are exactly what the credential access rules already cover from a different angle.

Left as is, because deciding which of the 28 deserve a rule is tuning work that needs the environment rather than a documentation pass. Recorded so the gap is visible instead of implied.

## Finding 5: The Rule ID Range Contradicts the File's Own Warning

The header comment in `rules/local_rules.xml` states that rule IDs 100100 to 200186 are occupied by the Sysmon MITRE rule files, and gives a command for checking before allocating new IDs.

The Falco rules are allocated 117000 to 117003, which is inside that range.

Whether they actually collide depends on which Sysmon rule files are installed on the manager, and this repository does not include them. It was not caught during the engagement, which suggests no collision occurred in practice, but a collision would be silent: Wazuh loads the last definition it reads and does not report the duplicate.

Run the command the file itself provides before reusing this ruleset anywhere else:

```bash
grep -r "rule id=" /var/ossec/etc/rules/ | grep -v "if_sid" | awk -F'"' '{print $2}' | sort -n | uniq -d
```

The auditd range, 210100 to 210114, sits clear of the documented occupied range.

## Finding 6: Seven Files Held No Content

The `test-cases/` folder contained five markdown files, each holding a single HTML comment pointing at `docs/DETECTION_TEST_CASES.md` and nothing else. The `notes/` folder held only a `.gitkeep`, and `screenshots/` held a `.gitkeep` alongside seven real screenshots.

All seven were removed. The test case content already lives in `docs/DETECTION_TEST_CASES.md`, which the README links to, so the folder promised a second source that did not exist. An empty folder in a portfolio repository reads as unfinished work rather than as room to grow.

## Finding 7: Two Copies of the Architecture Diagram Had Diverged

`diagrams/architecture.mermaid` and the diagram embedded in the README describe the same architecture differently. The standalone file labelled the hosts `VM1`, `VM2`, and `VM3` with no versions and described the transport as encrypted; the README named the roles, pinned every version, and described the transport as TLS.

The standalone file now matches the README exactly, verified by comparison rather than by eye, and the README states that the file exists so a reader knows which one to edit.

## Finding 8: Redaction Used Two Styles

Addresses were redacted in two different ways: `MANAGER_IP_REDACTED` in the configurations and setup documents, and a bare `REDACTED` in the sample alerts, where it stood for three different things depending on the field.

They are now `MANAGER_IP` in the agent configurations and `<AGENT_IP>` and `<ATTACKER_IP>` in the samples, listed in one table in the README. The manager address keeps the bare form because it sits inside an XML element, where angle brackets would break the file, and because that is the token the stock Wazuh agent configuration ships with. The distinction matters in the SSH sample, where `agent.ip` and `srcip` were both `REDACTED` while one is the monitored host and the other is the attacker.

## Finding 9: Naming Conventions Were Mixed

File names used three conventions at once: lower case with hyphens in `docs/` and `configs/`, spaces in screenshot names, and a doubled extension in `falco-rules.example.yaml`.

Everything is now lower case with underscores for configurations and samples, upper case with underscores for documents, and no spaces anywhere. The README also described a repository root named `wazuh-detection-lab/`, which is not the name of this repository, and that block was rewritten to match the real tree.

## Finding 10: Seven Screenshots Were Never Referenced

Only the cover image was linked, and through a URL encoded path that broke when the file was renamed. The other six included the dashboard that the README describes at length and a `wazuh-logtest` capture showing rule 210100 matching a real audit event.

All seven are now listed in the README, with the logtest capture called out as the strongest piece of evidence in the set.

## Finding 11: The Rule 210113 False Positive Was Attributed to Falco Alone

The README stated that rule 210113 fires because Falco creates raw sockets for its own eBPF monitoring, and listed an exclusion for `/usr/bin/falco` as the fix.

The dashboard breakdown shows the rule matching many processes. The executables raising it include a local binary with the highest count, then `/usr/bin/falco` at 393, `/usr/sbin/sshd` at 174, `/usr/lib/systemd/systemd` at 146, a user binary at 80, `/usr/bin/sudo` at 39, another local binary at 19, and `/usr/sbin/nginx` at 9.

The rule watches the `socket` syscall with `a0=0x2` and `a0=0xA`, which is any `AF_INET` or `AF_INET6` socket rather than a raw socket specifically. That matches ordinary network activity from ordinary daemons, which is why the count reaches into the hundreds per process.

Two consequences. The planned exclusion removes under a quarter of the noise, so it will look like it failed. And the rule as written does not detect what its description claims, since a normal TCP connection satisfies it just as well as a raw socket would.

Fixing it means narrowing the audit rule rather than excluding processes in Wazuh. Left to the engineer who owns the tuning, and recorded here so the exclusion is not shipped as a complete fix.

## Finding 12: Three Sets of Alert Volumes Disagreed

| Source                              | Falco              | auditd                  |
|-------------------------------------|--------------------|-------------------------|
| comments in `rules/local_rules.xml` | 12,080 in 24 hours | 128 or more in 24 hours |
| dashboard capture, Last 24 hours    | 8,034              | 1,712                   |

The rule file carried counts from an earlier observation and they drifted an order of magnitude apart from what the dashboard shows, in opposite directions.

The dashboard figures are now used in both places, and the README carries the full set of counters for the first time: 50,626 total alerts, 8,034 Falco, 7,956 Sysmon, 1,712 auditd, 7,825 at high severity.

Worth noting what those numbers say. The custom detections account for under a fifth of total volume. The rest is authentication noise from the internet, which the top triggered rules panel confirms.

## Finding 13: The Log Flow Document Named the Wrong Falco Path

`docs/LOG_FLOW.md` gave the Falco output as `/var/log/falco/falco_alerts.log`, twice, in its diagram and in its step list. Every other file in the repository, including the Falco configuration itself and both agent configurations, uses `/var/log/falco/falco_events.json`.

Following the log flow document would put the agent on a file Falco never writes, and the failure is silent: the agent reports no error for a `localfile` path that does not exist, so the pipeline simply produces no Falco alerts.

The document also described the Falco format as JSON or text and the agent log format as `json` or `syslog`. That is true of Falco in general and false of this deployment, where the rules depend on the JSON form. Corrected, with a note that changing the output format breaks rules 117000 to 117003.

## Finding 14: A Third Architecture Diagram Had Also Diverged

Beyond the two copies in finding 7, `docs/LOG_FLOW.md` carries a third diagram of the same architecture. It labelled the hosts `VM1`, `VM2`, and `VM3`, described the transport as encrypted rather than TLS, and described the manager as running rules `117xxx` with no mention of the auditd range that produces most of the custom detections.

It is now consistent with the other two on host naming and transport, and it names both rule ranges. It stays a separate diagram rather than a copy, because it shows the file paths and the agent hop, which the architecture diagram deliberately does not.

## Finding 15: The Screenshots Show Addresses the Documents Redact

`screenshots/Agent_Overview.png` displays both endpoint addresses in full, in the IP address column of the agent list. Those are the same values the documents and sample alerts carry as `<AGENT_IP>`.

The redaction in the text is therefore undone by the images. It is worth deciding one way or the other rather than leaving the two inconsistent: either crop that column and recapture, or accept that the addresses are published and drop the placeholders. The first is the safer choice for a public repository.

The same screenshot also shows agent group assignments, `default`, `Linux`, and `Windows`, which no document mentions. Groups decide which centralised configuration each agent receives, so they are worth documenting if any agent configuration is delivered that way.

## What Was Not Changed

**The audit rule behind 210113.** It watches `AF_INET` and `AF_INET6` sockets rather than raw sockets, which is why it matches ordinary daemons. Narrowing it is a change to the auditd ruleset on a running host. See finding 11.

**The XZ backdoor alert.** Falco flags sshd executing with `EXE_WRITABLE`, which matches the behavioural signature of CVE-2024-3094 but also matches ordinary daemon restart behaviour on some builds. It is already flagged for triage and it stays flagged. Calling it either way from the documentation would be guesswork.

**The auditd rule set itself.** 49 keys with 21 covered is a coverage decision, not a defect. See finding 4.

**Rule 100001.** Kept as inherited, now disclosed. See finding 3.
