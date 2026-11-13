# Wazuh Detection Engineering: Cybersecurity Track

**Team:** shadowsploit
**Builders :** Ian Kabaka & Ron Murithi
**Selected cards:** W1B (Too Many Failed Logins) and W3B (A New Program Was Installed)

> Items in [square brackets] are not filled in yet. Replace each one with a real value before submitting.

## SDG statement (draft)

Primary: **SDG 9** (resilient infrastructure). Small organisations often cannot afford a security team, so detecting password guessing and unexpected service installation early helps them keep their systems working. Secondary: **SDG 16** (accountable institutions): faster detection supports meeting breach-notification duties.
Note: this project detects suspicious activity. It does not make any organisation compliant.

## What this repo contains

| Path | Contents |
|---|---|
| `rules/` | Custom Wazuh rule XML for W1B and W3B |
| `configs/` | Non-secret agent configuration notes |
| `evidence/W1B/`, `evidence/W3B/` | Sanitized alert exports and screenshots, with a test table for each card |
| `docs/` | Lab setup notes and the cleanup record |

No real passwords, tokens or private network details are committed. The lab test account password is written as `<LAB_PASSWORD>`, and addresses as `<MANAGER_IP>` and `<VM_IP>`.

## Lab setup

| Component | Detail |
|---|---|
| Wazuh manager, indexer, dashboard | Linux VM in VirtualBox, version [VERSION] |
| Monitored endpoint | Windows VM `LABWIN01` (agent ID 002), Wazuh agent [VERSION] |
| Test source | The builder's PC, on the same bridged LAN as both VMs |
| Event channels collected | Application, Security and System (confirmed in the agent's `ossec.conf`) |

**Time zones.** `LABWIN01` is set to Pacific Standard Time (UTC-8). The dashboard displays Nairobi time (UTC+3). To convert a VM time to dashboard time, add 11 hours. Inside each event, `data.win.system.systemTime` is stored in UTC.

**Authorization.** [State whether the organizers supplied this lab or approved the local VirtualBox arrangement, with the name of the person who approved it.]

## W1B: Too Many Failed Logins

**Detects:** five or more Windows Event 4625 failures from the same source IP within two minutes.

**Background.** Event 4625 means "an account failed to log on". One failure is usually a typo. Many from one source in a short time can indicate password guessing. Failures alone do not prove a breach.

**Rule:** [Paste the exact contents of the W1B rules from `/var/ossec/etc/rules/local_rules.xml`. To print them on the manager, run `grep -n -A12 'id="1001' /var/ossec/etc/rules/local_rules.xml`.]

**How the rule works:** [2 to 4 sentences in your own words: what the parent rule matches, what `frequency` and `timeframe` mean, and why the rule groups by source IP.]

**Required alert fields:** source IP, username, endpoint, timestamp, rule ID and description. [Confirm each in a screenshot of an expanded alert.]

**Tests** (wait over two minutes between tests so correlation state resets):

| # | Test | Expected | Observed | Evidence |
|---|---|---|---|---|
| 1 | One failure | Built-in rule only, no custom alert | failed logon for id 100900 | video |
| 2 | Four failures within two minutes | No custom alert | failed logon for id 100900 | vudei |
| 3 | Fifth failure inside the window | Custom alert 100101 | repeated failed logon id:100901 | video |

**Limitations:** an attacker who spaces attempts more than two minutes apart, or spreads them across many source IPs, would not trigger this rule. Users sharing one NAT address could cause false alerts.

## W3B: A New Program Was Installed

**Detects:** Windows System event 7045 (a service was installed) where the service's program is outside the Windows directory.

**Background.** Attackers sometimes install a service so their program survives a reboot. Legitimate software also installs services outside `C:\Windows`, for example the Wazuh agent itself. An alert from this rule means "worth investigating", not "this is malware".

**Source and fields.** The System channel is collected by the agent. Built-in rule 61138 ("New Windows Service Created") recognises the event, and the custom rule builds on it. Fields used: `win.system.eventID`, `win.eventdata.imagePath`, and the service name and account fields [confirm the exact field names from an expanded alert].

### Rule (`rules/w3b.xml`)

```xml
<group name="windows,custom,w3b,">
  <rule id="100110" level="10">
    <if_sid>61138</if_sid>
    <field name="win.system.eventID">^7045$</field>
    <field name="win.eventdata.imagePath" type="pcre2" negate="yes">(?i)^(?:\\?")?(?:[a-z]:\\{1,2}Windows\\{1,2}|%SystemRoot%\\{1,2}|%windir%\\{1,2}|\\{1,2}SystemRoot\\{1,2}|system32\\{1,2})</field>
    <description>New service installed with binary outside the Windows directory</description>
  </rule>
</group>
```



### How the rule works

- `if_sid 61138` restricts the rule to events Wazuh already recognises as a new service.
- The `eventID` line makes sure the event is 7045.
- The `imagePath` line uses `negate="yes"`, so the rule fires when the path does **not** start with a Windows-directory form.
- The pattern accepts these Windows-directory forms: `C:\Windows\`, `%SystemRoot%\`, `%windir%\`, `\SystemRoot\` and a relative `system32\`. It ignores upper or lower case and allows an optional leading quote.
- The backslash after `Windows` matters: it means `C:\Windows.old\` is not treated as the Windows directory.
- `\\{1,2}` allows one or two backslashes because Wazuh stores the path JSON-escaped (`C:\\LabTest\\benign.exe`), which was visible in the dashboard.

### Design findings from real data

- The VM's own VirtualBox driver service is registered as `\SystemRoot\System32\drivers\VBoxSF.sys`. That is inside the Windows directory, so the pattern had to accept the `\SystemRoot\` form to avoid a false alert.
- The dashboard showed doubled backslashes, so the pattern accepts both single and doubled forms.

### Live test results

The tests below were run on `LABWIN01` after the rule was loaded. Times are dashboard time (UTC+3); subtract 11 hours for VM time.

| Service | Path | Expected | Observed | Dashboard time |
|---|---|---|---|---|
| LabTestSvc6 | `C:\LabTest\benign.exe` | Alert 100110 | Alert 100110, level 10 | 07:09:43 |
| LabTestSvc7 | `C:\Users\Public\other.exe` | Alert 100110 (variation) | Alert 100110, level 10 | 07:09:43 |
| LabTestSvc8 | `C:\Windows.old\x.exe` | Alert 100110 (similar name, different folder) | Alert 100110, level 10 | 07:09:43 |
| LabTestSvc9 | `C:\Windows\System32\x.exe` | No alert (benign) | Built-in 61138 only | 07:09:46 |

Earlier events, created before the rule existed, appear in the dashboard under the built-in rule 61138 only: `LabTestSvc2` (06:50:48) and an existing Windows Remediation service (00:28:25). `LabTestSvc2` shows that live collection worked before the custom rule was loaded.

The Windows Remediation service lies outside `C:\Windows`, so it is expected to match the rule. This was not tested live because it predates the rule. It illustrates that a legitimate service can meet the condition.

**Required alert fields:** service name, binary path and service account, plus agent, timestamp and rule ID. [Confirm the account field in an expanded alert and attach the screenshot.]

**Event Viewer evidence for `LabTestSvc1`:** Windows logged the event at 13:08:19 VM time with path `C:\LabTest\benign.exe` and account LocalSystem. It did not appear in Wazuh because the agent was disconnected at the time (see incident below).

### Limitations

- A path such as `C:\Windows\..\Temp\x.exe` or an 8.3 short name could slip past a text match.
- Any legitimate installer outside `C:\Windows` raises an alert. The alert says "investigate", not "malicious".
- The rule fires when the service is created. It does not show whether the service was ever started.
- Driver services without an account have an empty account field.

### Cleanup

```powershell
sc.exe delete LabTestSvc1   # repeat for LabTestSvc2, 6, 7, 8 and 9
sc.exe query LabTestSvc1    # expect error 1060, service does not exist
```



Cleanup happens after evidence is saved and after judges' inspection if they may ask for a repeat.

## Incident log: agent lost connection to the manager

- **Symptom:** the agent log showed repeated "connection timed out" errors to the old manager address.
- **Cause:** the manager's address had changed (it uses a dynamic address), while the agent's `ossec.conf` still pointed at the old one.
- **Diagnosis:** a timeout points to nothing answering at that address, not a refusal. `ipconfig` on the VM and `ip a` on the manager showed the new address.
- **Fix:** the manager address in `ossec.conf` was updated and the agent service restarted. The log then showed "Connected to the server".
- **Prevention:** reserve a fixed address for the manager.

## Reproduction

1. Set up a Wazuh manager and a Windows VM with the agent, with the System and Security channels collected.
2. Add the rule(s) to `/var/ossec/etc/rules/local_rules.xml` on the manager, run `/var/ossec/bin/wazuh-analysisd -t`, then `systemctl restart wazuh-manager`.
3. On the Windows VM (admin PowerShell), create the test services in the W3B table using `sc.exe create <name> binPath= "<path>"`.
4. In the dashboard, search `data.win.system.eventID:7045` for the agent and check the rule ID of each alert.
5. Clean up using the commands above.

