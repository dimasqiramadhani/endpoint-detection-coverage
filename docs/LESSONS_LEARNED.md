# Lessons Learned

Technical notes from the implementation. Some of these are specific to this engagement, others are generally applicable to Wazuh deployments.

---

## Detection Engineering

**Wazuh's built in auditd rule suppresses all events by default.** Rule 80700 ("Audit: Messages grouped") catches every auditd SYSCALL event at level 0, which means no alert is generated. Custom child rules with `<if_sid>80700</if_sid>` are required to surface specific events as alerts. This is not immediately obvious and caused the initial period where auditd showed 0 alerts despite events flowing into the indexer.

**wazuh-logtest should be the first debugging step, not the last.** When a log source appears to be working (agent connected, events visible in raw logs, Discover showing hits) but no alerts appear in Security Events, `wazuh-logtest` on the Manager immediately shows which rule fires and at what level. Skipping directly to it avoids a long process of checking configs that are not the problem.

**Rule ID space is not empty above 100000.** Community and vendor rule packs commonly use the 100000+ range. In this deployment, IDs 100100-200186 were already occupied by preinstalled Sysmon MITRE rule files. Custom rules should not be assigned IDs without first checking what is in use: `grep -r "rule id=" /var/ossec/etc/rules/ | grep -v "if_sid" | awk -F'"' '{print $2}' | sort -n | tail -20`.

**Falco JSON output removes the need for custom decoders.** Configuring Falco with `file_output: enabled: true` and JSON format means Wazuh's built in JSON decoder handles all field extraction. The alternative, plain text output, would require writing and maintaining custom decoders for every field. JSON is the right choice.

**False positives should be documented, not ignored, and the cause matters as much as the symptom.** Two notable ones here. Rule 210113 was first written off as Falco creating sockets for its own monitoring, but the dashboard shows it matching sshd, systemd, sudo, and nginx as well, because the audit rule behind it watches every `AF_INET` and `AF_INET6` socket rather than raw sockets specifically. The planned per process exclusion would therefore have removed a fraction of the noise and looked like a failed fix. The second is the XZ Backdoor Falco alert, firing on the order of three thousand times in 24 hours, a volume that points at ordinary sshd behaviour matching the `EXE_WRITABLE` pattern rather than at a compromise. Both stay on the known issues list.

The general lesson is the one that cost the most time: an assumed cause that fits the first example is not a diagnosis. Checking the full breakdown before writing the exclusion would have caught it immediately.

## Log Collection

**The log_format value in ossec.conf must match the actual log format exactly.** Using `eventlog` instead of `eventchannel` for Sysmon silently drops all events. Using `syslog` instead of `audit` for auditd causes parsing failures. There is no error message in most cases, events simply do not appear.

**Sysmon requires both a binary and a config file.** Installing Sysmon without a config file results in minimal logging. The config file defines which events to capture and which to filter. Network connection logging (Event ID 3) is disabled by default in many configs and must be explicitly enabled.

**Falco generates high event volume from the start.** The default Falco ruleset, combined with incubating rules, produces thousands of alerts per day on an active Linux server. The "Unexpected UDP Traffic" rule in particular fires frequently because sshd generates UDP traffic during normal connection handling. Rule tuning should be part of the initial deployment, not deferred.

## Infrastructure

**All in One Wazuh is workable but resource sensitive.** Running Manager, Indexer, and Dashboard on a single server requires adequate resources. The Indexer (OpenSearch) is the primary memory consumer. With external attack traffic generating high alert volume, storage consumption should be monitored closely. Log retention policies should be configured early.

**Real external traffic provides better validation than synthetic tests.** Running the environment with externally reachable IPs meant the detection pipeline was tested against real attack patterns (SSH brute force, port scanning, credential stuffing) from day one. This surfaces tuning issues that synthetic test scripts often miss.

## Process

**Testing before production handover should cover both positive and negative cases.** Positive cases confirm that expected detections fire. Negative cases confirm that legitimate activity does not generate excessive noise. Both matter for client confidence.

**Documenting rule intent at the time of writing is faster than reconstructing it later.** Comments in `local_rules.xml` explaining what each rule matches and why a specific audit key or pattern was chosen saves significant time during review or when another engineer picks up the work.
