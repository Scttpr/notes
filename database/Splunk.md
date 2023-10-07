- **URL :** https://www.splunk.com/
- **Description :** Splunk collecte, indexe et met en corrélation des données en temps réel dans des archives recherchables, permettant de générer des graphiques, des rapports, des alertes, des tableaux de bord et des infographies
- **Platforms :** *
- **Category :** [[Tools]]
- **Tags :** [[SIEM]], [[Windows]], [[Linux]], [[Sigma]]

## Hunting with Sigma

#### Example 1: Hunting for MiniDump Function Abuse to Dump LSASS's Memory (comsvcs.dll via rundll32)

A Sigma rule named `proc_access_win_lsass_dump_comsvcs_dll.yml` can be found inside the `C:\Tools\chainsaw\sigma\rules\windows\process_access` directory of the `previous` section's target.

This Sigma rule detects adversaries leveraging the `MiniDump` export function of `comsvcs.dll` via `rundll32` to perform a memory dump from LSASS.

We can translate this rule into a Splunk search with `sigmac` (available at `C:\Tools\sigma-0.21\tools`) as follows.

Example 1: Hunting for MiniDump Function Abuse to Dump LSASS's Memory (comsvcs.dll via rundll32)

```powershell-session
PS C:\Tools\sigma-0.21\tools> python sigmac -t splunk C:\Tools\chainsaw\sigma\rules\windows\process_access\proc_access_win_lsass_dump_comsvcs_dll.yml -c .\config\splunk-windows.yml
(TargetImage="*\\lsass.exe" SourceImage="C:\\Windows\\System32\\rundll32.exe" CallTrace="*comsvcs.dll*")
```

Let's now navigate to the bottom of this section and click on `Click here to spawn the target system!`. Then, let's navigate to `http://[Target IP]:8000`, open the "Search & Reporting" application, and submit the Splunk search `sigmac` provided us with.

![](https://academy.hackthebox.com/storage/modules/234/splunk_1.png)

The Splunk search provided by `sigmac` was indeed able to detect MiniDump function abuse to dump LSASS's memory.

---

#### Example 2: Hunting for Notepad Spawning Suspicious Child Process

A Sigma rule named `proc_creation_win_notepad_susp_child.yml` can be found inside the `C:\Rules\sigma` directory of the `previous` section's target.

This Sigma rule detects `notepad.exe` spawning a suspicious child process.

We can translate this rule into a Splunk search with `sigmac` (available at `C:\Tools\sigma-0.21\tools`) as follows.

Example 2: Hunting for Notepad Spawning Suspicious Child Process

```powershell-session
PS C:\Tools\sigma-0.21\tools> python sigmac -t splunk C:\Rules\sigma\proc_creation_win_notepad_susp_child.yml -c .\config\splunk-windows.yml
(ParentImage="*\\notepad.exe" (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe" OR Image="*\\mshta.exe" OR Image="*\\cscript.exe" OR Image="*\\wscript.exe" OR Image="*\\taskkill.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\calc.exe"))
```

Let's now navigate to the bottom of this section and click on `Click here to spawn the target system!`, if we haven't done that already. Then, let's navigate to `http://[Target IP]:8000`, open the "Search & Reporting" application, and submit the Splunk search `sigmac` provided us with.

![](https://academy.hackthebox.com/storage/modules/234/splunk_2.png)

The Splunk search provided by `sigmac` was indeed able to detect `notepad.exe` spawning suspicious processes (such as PowerShell).

---

Please note that more frequently than not you will have to tamper with Sigma's config files (available inside the `C:\Tools\sigma-0.21\tools\config` directory of the previous section's target) in order for the SIEM queries to be readily usable.

## Queries exemples

### Detecting Responder-like Attacks

```shell-session
index=main earliest=1690290078 latest=1690291207 SourceName=LLMNRDetection
| table _time, ComputerName, SourceName, Message
```

[Sysmon Event ID 22](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90022) can also be utilized to track DNS queries associated with non-existent/mistyped file shares.

```shell-session
index=main earliest=1690290078 latest=1690291207 EventCode=22 
| table _time, Computer, user, Image, QueryName, QueryResults
```

Additionally, remember that [Event 4648](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648) can be used to detect explicit logons to rogue file shares which attackers might use to gather legitimate user credentials.

```shell-session
index=main earliest=1690290814 latest=1690291207 EventCode IN (4648) 
| table _time, EventCode, source, name, user, Target_Server_Name, Message
| sort 0 _time
```

### Detecting Kerberoasting

#### Benign TGS Requests
```shell-session
index=main earliest=1690388417 latest=1690388630 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc) 
| dedup RecordNumber 
| rex field=user "(?<username>[^@]+)"
| table _time, ComputerName, EventCode, name, username, Account_Name, Account_Domain, src_ip, service_name, Ticket_Options, Ticket_Encryption_Type, Target_Server_Name, Additional_Information
```

**Search Breakdown**:
- `index=main earliest=1690388417 latest=1690388630`: This filters the search to only include events from the main index that occurred between the specified earliest and latest epoch timestamps.
- `EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)`: This further filters the search to only include events with an `EventCode` of `4648` `or` an `EventCode` of `4769` with a `service_name` of `iis_svc`.
- `| dedup RecordNumber`: This removes duplicate events based on the `RecordNumber` field.
- `| rex field=user "(?<username>[^@]+)"`: This extracts the `username` portion of the `user` field using a regular expression and stores it in a new field called `username`.
- `| table _time, ComputerName, EventCode, name, username, Account_Name, Account_Domain, src_ip, service_name, Ticket_Options, Ticket_Encryption_Type, Target_Server_Name, Additional_Information`: This displays the specified fields in tabular format.

#### Detecting Kerberoasting - SPN Querying

```shell-session
index=main earliest=1690448444 latest=1690454437 source="WinEventLog:SilkService-Log" 
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter 
| search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
```

#### Detecting Kerberoasting - TGS Requests

```shell-session
index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| bin span=2m _time 
| search username!=*$ 
| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username
| where !match(Events,"4648")
```

**Search Breakdown**:
- `index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)`: Filters the search to only include events from the `main` index that occurred between the specified earliest and latest epoch timestamps. It further filters the search to only include events with an `EventCode` of `4648` or an `EventCode` of `4769` with a `service_name` of `iis_svc`.
- `| dedup RecordNumber`: Removes duplicate events based on the `RecordNumber` field.
- `| rex field=user "(?<username>[^@]+)"`: Extracts the `username` portion of the `user` field using a regular expression and stores it in a new field called `username`.
- `| bin span=2m _time`: Bins the events into 2-minute intervals based on the `_time` field.
- `| search username!=*$`: Filters out events where the `username` field ends with a `$`.
- `| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username`: Groups the events by the `_time` and `username` fields, and creates new fields that contain the `unique` values of the `EventCode`, `service_name`, `Additional_Information`, and `Target_Server_Name` fields within each group.
- `| where !match(Events,"4648")`: Filters out events that have the value `4648` in the Events field.

#### Detecting Kerberoasting Using Transactions - TGS Requests

```shell-session
index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| search username!=*$ 
| transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769) 
| where closed_txn=0 AND EventCode = 4769
| table _time, EventCode, service_name, username
```

**Search Breakdown**:

This Splunk search query is different from the previous query primarily due to the use of the `transaction` command, which groups events into transactions based on specified fields and criteria.
- `index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)`: Filters the search to only include events from the `main` index that occurred between the specified earliest and latest epoch timestamps. It further filters the search to only include events with an `EventCode` of `4648` or an `EventCode` of `4769` with a `service_name` of `iis_svc`.
- `| dedup RecordNumber`: Removes duplicate events based on the `RecordNumber` field.
- `| rex field=user "(?<username>[^@]+)"`: Extracts the `username` portion of the `user` field using a regular expression and stores it in a new field called `username`.
- `| search username!=*$`: Filters out events where the `username` field ends with a `$`.
- `| transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769)`: Groups events into `transactions` based on the `username` field. The `keepevicted=true` option includes events that do not meet the transaction criteria. The `maxspan=5s` option sets the maximum time duration of a transaction to 5 seconds. The `endswith=(EventCode=4648)` and `startswith=(EventCode=4769)` options specify that transactions should start with an event with `EventCode 4769` and end with an event with `EventCode 4648`.
- `| where closed_txn=0 AND EventCode = 4769`: Filters the results to only include transactions that are not closed (`closed_txn=0`) and have an `EventCode` of `4769`.
- `| table _time, EventCode, service_name, username`: Displays the remaining events in tabular format with the specified fields.

### Detecting AS-REPRoasting

#### Detecting AS-REPRoasting - Querying Accounts With Pre-Auth Disabled

```shell-session
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:SilkService-Log" 
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter 
| search SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"
```

#### Detecting AS-REPRoasting - TGT Requests For Accounts With Pre-Auth Disabled

```shell-session
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type
```

**Search Breakdown**:
- `index=main earliest=1690392745 latest=1690393283 source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0`: Filters the search to only include events from the `main` index that occurred between the specified earliest and latest epoch timestamps. It further filters the search to only include events with a source of `WinEventLog:Security`, an `EventCode` of `4768`, and a `Pre_Authentication_Type` of `0`.
- `| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"`: Uses a regular expression to extract the `src_ip` (source IP address) field. The expression matches an optional `"::ffff:"` prefix followed by an IP address in dotted decimal notation. This step handles IPv4-mapped IPv6 addresses by extracting the IPv4 portion.
- `| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type`: Displays the remaining events in tabular format with the specified fields.