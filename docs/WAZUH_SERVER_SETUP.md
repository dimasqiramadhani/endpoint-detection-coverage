# Wazuh Server Setup (ubnsrv-aio)

## Deployment Method

Wazuh All in One installation using the official Wazuh installation script. Installs Manager, Indexer, and Dashboard on a single server.

## System Requirements

The server used for this deployment:
* RAM: 16 GB
* CPU: 2 cores (upgraded from initial spec due to Indexer memory requirements)
* Storage: 128 GB
* OS: Linux

Minimum recommended for All in One: 4 GB RAM. 8 GB is more comfortable under real alert load.

## Installation

```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

Wazuh version installed: **v4.14.5 (rc1)**

After installation, the Dashboard is accessible at `https://<server-ip>:443`. Default credentials are printed during installation.

## After Installation Verification

```bash
# Verify all services running
systemctl status wazuh-manager
systemctl status wazuh-indexer
systemctl status wazuh-dashboard
```

```bash
# Verify agent connectivity
sudo /var/ossec/bin/agent_control -lc
```

Expected output:
```
Wazuh agent_control. List of available agents:
   ID: 000, Name: ubnsrv-aio (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: ubnsrv-agent, IP: any, Active
   ID: 002, Name: winsrv-agent, IP: any, Active
```

## Wazuh Version Info

```
WAZUH_VERSION="v4.14.5"
WAZUH_REVISION="rc1"
WAZUH_TYPE="server"
```

## Configuration Files

| File                                        | Purpose                        |
|---------------------------------------------|--------------------------------|
| `/var/ossec/etc/ossec.conf`                 | Main Manager configuration     |
| `/var/ossec/etc/rules/local_rules.xml`      | Custom detection rules         |
| `/var/ossec/etc/decoders/local_decoder.xml` | Custom decoders (not modified) |
| `/var/ossec/etc/lists/`                     | CDB lookup lists               |

## Custom Rules Deployed

Rules 117000-117003 (Falco) and 210100-210114 (auditd) were added to `/var/ossec/etc/rules/local_rules.xml`. See [CUSTOM_RULES.md](CUSTOM_RULES.md) for full documentation.

After any rule change, restart the Manager:
```bash
sudo systemctl restart wazuh-manager
```

## Preinstalled Rule Files

The following custom rule files were already present on the server and cover MITRE ATT&CK techniques for Sysmon events:

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

These files occupy rule IDs 100100-200186. Custom rules in this implementation use the 210100+ range to avoid conflicts.
