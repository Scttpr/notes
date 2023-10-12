- **URL :** 
- **Description :** `Windows Event Logs` are an intrinsic part of the Windows Operating System, storing logs from different components of the system including the system itself, applications running on it, ETW providers, services, and others.
- **Platforms :** [[Windows]]
- **Category :** [[Documentation]]
- **Tags :** [[DFIR]]

## Notes

- Default location : `C:\Windows\System32\winevt\logs`

#### Windows Event Logs Parsing Using EvtxECmd (EZ-Tool)

`EvtxECmd` (available at `C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxeCmd`) is another brainchild of Eric Zimmerman, tailored for Windows Event Log files (EVTX files). With this tool at our disposal, we can extract specific event logs or a range of events from an EVTX file, converting them into more digestible formats like JSON, XML, or CSV.

Let's initiate the help menu of EvtxECmd to familiarize ourselves with the various options. The command to access the help section is as follows.

Windows Event Logs Parsing Using EvtxECmd (EZ-Tool)

```powershell-session
PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxeCmd> .\EvtxECmd.exe -h
Description:
  EvtxECmd version 1.5.0.0

  Author: Eric Zimmerman (saericzimmerman@gmail.com)
  https://github.com/EricZimmerman/evtx

  Examples: EvtxECmd.exe -f "C:\Temp\Application.evtx" --csv "c:\temp\out" --csvf MyOutputFile.csv
            EvtxECmd.exe -f "C:\Temp\Application.evtx" --csv "c:\temp\out"
            EvtxECmd.exe -f "C:\Temp\Application.evtx" --json "c:\temp\jsonout"

            Short options (single letter) are prefixed with a single dash. Long commands are prefixed with two dashes

Usage:
  EvtxECmd [options]

Options:
  -f <f>           File to process. This or -d is required
  -d <d>           Directory to process that contains evtx files. This or -f is required
  --csv <csv>      Directory to save CSV formatted results to
  --csvf <csvf>    File name to save CSV formatted results to. When present, overrides default name
  --json <json>    Directory to save JSON formatted results to
  --jsonf <jsonf>  File name to save JSON formatted results to. When present, overrides default name
  --xml <xml>      Directory to save XML formatted results to
  --xmlf <xmlf>    File name to save XML formatted results to. When present, overrides default name
  --dt <dt>        The custom date/time format to use when displaying time stamps [default: yyyy-MM-dd HH:mm:ss.fffffff]
  --inc <inc>      List of Event IDs to process. All others are ignored. Overrides --exc Format is 4624,4625,5410
  --exc <exc>      List of Event IDs to IGNORE. All others are included. Format is 4624,4625,5410
  --sd <sd>        Start date for including events (UTC). Anything OLDER than this is dropped. Format should match --dt
  --ed <ed>        End date for including events (UTC). Anything NEWER than this is dropped. Format should match --dt
  --fj             When true, export all available data when using --json [default: False]
  --tdt <tdt>      The number of seconds to use for time discrepancy detection [default: 1]
  --met            When true, show metrics about processed event log [default: True]
  --maps <maps>    The path where event maps are located. Defaults to 'Maps' folder where program was executed
                   [default: C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxeCmd\Maps]
  --vss            Process all Volume Shadow Copies that exist on drive specified by -f or -d [default: False]
  --dedupe         Deduplicate -f or -d & VSCs based on SHA-1. First file found wins [default: True]
  --sync           If true, the latest maps from https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps are
                   downloaded and local maps updated [default: False]
  --debug          Show debug information during processing [default: False]
  --trace          Show trace information during processing [default: False]
  --version        Show version information
  -?, -h, --help   Show help and usage information
```

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_winevt4_.png)

#### Maps in EvtxECmd

Maps in `EvtxECmd` are pivotal. They metamorphose customized data into standardized fields in the CSV (and JSON) data. This granularity and precision are indispensable in forensic investigations, enabling analysts to interpret and extract salient information from Windows Event Logs with finesse.

Standardized fields in maps:

- `UserName`: Contains information about user and/or domain found in various event logs
- `ExecutableInfo`: Contains information about process command line, scheduled tasks etc.
- `PayloadData1,2,3,4,5,6`: Additional fields to extract and put contextual data from event logs
- `RemoteHost`: Contains information about IP address

`EvtxECmd` plays a significant role in:

- Converting the unique part of an event, known as EventData, into a more standardized and human-readable format.
- Ensuring that the map files are tailored to specific event logs, such as Security, Application, or custom logs, to handle differences in event structures and data.
- Using a unique identifier, the Channel element, to specify which event log a particular map file is designed for, preventing confusion when event IDs are reused across different logs.

To ensure the most recent maps are in place before converting the EVTX files to CSV/JSON, employ the command below.

Maps in EvtxECmd

```powershell-session
PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxeCmd> .\EvtxECmd.exe --sync
EvtxECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/evtx

Checking for updated maps at https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps...

Updates found!

New maps
Application_ESENT_216
CiscoSecureEndpoint-Events_CiscoSecureEndpoint_100
CiscoSecureEndpoint-Events_CiscoSecureEndpoint_1300
CiscoSecureEndpoint-Events_CiscoSecureEndpoint_1310
Kaspersky-Security_OnDemandScan_3023
Kaspersky-Security_Real-Time_File_Protection_3023
Microsoft-Windows-Hyper-V-VMMS-Admin_Microsoft-Windows-Hyper-V-VMMS_13002
Microsoft-Windows-Hyper-V-VMMS-Admin_Microsoft-Windows-Hyper-V-VMMS_18304
Microsoft-Windows-Hyper-V-VMMS-Admin_Microsoft-Windows-Hyper-V-Worker_13003
Microsoft-Windows-Hyper-V-Worker-Admin_Microsoft-Windows-Hyper-V-Worker_18303
Microsoft-Windows-Hyper-V-Worker-Admin_Microsoft-Windows-Hyper-V-Worker_18504
Microsoft-Windows-Hyper-V-Worker-Admin_Microsoft-Windows-Hyper-V-Worker_18512
Microsoft-Windows-Windows-Defender-Operational_Microsoft-Windows-Windows-Defender_2050
PowerShellCore-Operational_PowerShellCore_4104
Security_Microsoft-Windows-Security-Auditing_6272
Security_Microsoft-Windows-Security-Auditing_6273

Updated maps
Microsoft-Windows-Hyper-V-Worker-Admin_Microsoft-Windows-Hyper-V-Worker_18500
Microsoft-Windows-Hyper-V-Worker-Admin_Microsoft-Windows-Hyper-V-Worker_18502
Microsoft-Windows-Hyper-V-Worker-Admin_Microsoft-Windows-Hyper-V-Worker_18508
Microsoft-Windows-Hyper-V-Worker-Admin_Microsoft-Windows-Hyper-V-Worker_18514
Microsoft-Windows-SMBServer-Security_Microsoft-Windows-SMBServer_551
Security_Microsoft-Windows-Security-Auditing_4616
```

With the latest maps integrated, we're equipped to infuse contextual information into distinct fields, streamlining the log analysis process. Now, it's time to transmute the logs into a format that's more palatable.

To render the EVTX files more accessible, we can employ `EvtxECmd` to seamlessly convert event log files into user-friendly formats like JSON or CSV.

For instance, the command below facilitates the conversion of the `C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx` file to a CSV file:

Maps in EvtxECmd

```powershell-session
PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxeCmd> .\EvtxECmd.exe -f "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx" --csv "C:\Users\johndoe\Desktop\forensic_data\event_logs\csv_timeline" --csvf kape_event_log.csv
EvtxECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/evtx

Command line: -f C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx --csv C:\Users\johndoe\Desktop\forensic_data\event_logs\csv_timeline --csvf kape_event_log.csv

Warning: Administrator privileges not found!

CSV output will be saved to C:\Users\johndoe\Desktop\forensic_data\event_logs\csv_timeline\kape_event_log.csv

Processing C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx...

Event log details
Flags: None
Chunk count: 28
Stored/Calculated CRC: 3EF9F1C/3EF9F1C
Earliest timestamp: 2023-09-07 08:23:18.4430130
Latest timestamp:   2023-09-07 08:33:00.0069805
Total event log records found: 1,920

Records included: 1,920 Errors: 0 Events dropped: 0

Metrics (including dropped events)
Event ID        Count
1               95
2               76
3               346
4               1
8               44
10              6
11              321
12              674
13              356
16              1

Processed 1 file in 8.7664 seconds
```

After importing the resultant CSV into `Timeline Explorer`, we should see the below.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_winevt6.png)

**Executable Information**:

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_winevt7.png)

#### Investigating Windows Event Logs with EQL

[Endgame's Event Query Language (EQL)](https://github.com/endgameinc/eqllib) is an indispensable tool for sifting through event logs, pinpointing potential security threats, and uncovering suspicious activities on Windows systems. EQL offers a structured language that facilitates querying and correlating events across multiple log sources, including the Windows Event Logs.

Currently, the EQL module is compatible with Python versions 2.7 and 3.5+. If you have a supported Python version installed, execute the following command.

Investigating Windows Event Logs with EQL

```cmd-session
C:\Users\johndoe>pip install eql
```

Should Python be properly configured and included in your PATH, eql should be accessible. To verify this, execute the command below.

Investigating Windows Event Logs with EQL

```cmd-session
C:\Users\johndoe>eql --version
eql 0.9.18
```

Within EQL's repository (available at `C:\Users\johndoe\Desktop\eqllib-master`), there's a PowerShell module brimming with essential functions tailored for parsing Sysmon events from Windows Event Logs. This module resides in the `utils` directory of `eqllib`, and is named `scrape-events.ps1`.

From the EQL directory, initiate the scrape-events.ps1 module with the following command:

Investigating Windows Event Logs with EQL

```powershell-session
PS C:\Users\johndoe\Desktop\eqllib-master\utils> import-module .\scrape-events.ps1 
```

By doing so, we activate the `Get-EventProps` function, which is instrumental in parsing event properties from Sysmon logs. To transform, for example, `C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx` into a JSON format suitable for EQL queries, execute the command below.

Investigating Windows Event Logs with EQL

```powershell-session
PS C:\Users\johndoe\Desktop\eqllib-master\utils> Get-WinEvent -Path C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx -Oldest | Get-EventProps | ConvertTo-Json | Out-File -Encoding ASCII -FilePath C:\Users\johndoe\Desktop\forensic_data\event_logs\eql_format_json\eql-sysmon-data-kape.json
```

This action will yield a JSON file, primed for EQL queries.

Let's now see how we could have identified user/group enumeration through an EQL query against the JSON file we created.

Investigating Windows Event Logs with EQL

```cmd-session
C:\Users\johndoe>eql query -f C:\Users\johndoe\Desktop\forensic_data\event_logs\eql_format_json\eql-sysmon-data-kape.json "EventId=1 and (Image='*net.exe' and (wildcard(CommandLine, '* user*', '*localgroup *', '*group *')))"
{"CommandLine": "net  localgroup \"Remote Desktop Users\" backgroundTask /add", "Company": "Microsoft Corporation", "CurrentDirectory": "C:\\Temp\\", "Description": "Net Command", "EventId": 1, "FileVersion": "10.0.19041.1 (WinBuild.160101.0800)", "Hashes": "MD5=0BD94A338EEA5A4E1F2830AE326E6D19,SHA256=9F376759BCBCD705F726460FC4A7E2B07F310F52BAA73CAAAAA124FDDBDF993E,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07", "Image": "C:\\Windows\\System32\\net.exe", "IntegrityLevel": "High", "LogonGuid": "{b5ae2bdd-9f94-64ec-0000-002087490200}", "LogonId": "0x24987", "ParentCommandLine": "C:\\Windows\\system32\\cmd.exe /c install.bat", "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentProcessGuid": "{b5ae2bdd-8a0f-64f9-0000-00104cfc4700}", "ParentProcessId": "6540", "ProcessGuid": "{b5ae2bdd-8a14-64f9-0000-0010e8804800}", "ProcessId": "3808", "Product": "Microsoft? Windows? Operating System", "RuleName": null, "TerminalSessionId": "1", "User": "HTBVM01\\John Doe", "UtcTime": "2023-09-07 08:30:12.178"}
{"CommandLine": "net  users  ", "Company": "Microsoft Corporation", "CurrentDirectory": "C:\\Temp\\", "Description": "Net Command", "EventId": 1, "FileVersion": "10.0.19041.1 (WinBuild.160101.0800)", "Hashes": "MD5=0BD94A338EEA5A4E1F2830AE326E6D19,SHA256=9F376759BCBCD705F726460FC4A7E2B07F310F52BAA73CAAAAA124FDDBDF993E,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07", "Image": "C:\\Windows\\System32\\net.exe", "IntegrityLevel": "High", "LogonGuid": "{b5ae2bdd-9f94-64ec-0000-002087490200}", "LogonId": "0x24987", "ParentCommandLine": "cmd.exe /c ping -n 10 127.0.0.1 > nul && net users > users.txt && net localgroup > groups.txt && ipconfig >ipinfo.txt && netstat -an >networkinfo.txt && del /F /Q C:\\Temp\\discord.exe", "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentProcessGuid": "{b5ae2bdd-8a19-64f9-0000-0010c5914800}", "ParentProcessId": "4040", "ProcessGuid": "{b5ae2bdd-8a22-64f9-0000-0010c59f4800}", "ProcessId": "5364", "Product": "Microsoft? Windows? Operating System", "RuleName": null, "TerminalSessionId": "1", "User": "HTBVM01\\John Doe", "UtcTime": "2023-09-07 08:30:26.851"}
{"CommandLine": "net  localgroup  ", "Company": "Microsoft Corporation", "CurrentDirectory": "C:\\Temp\\", "Description": "Net Command", "EventId": 1, "FileVersion": "10.0.19041.1 (WinBuild.160101.0800)", "Hashes": "MD5=0BD94A338EEA5A4E1F2830AE326E6D19,SHA256=9F376759BCBCD705F726460FC4A7E2B07F310F52BAA73CAAAAA124FDDBDF993E,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07", "Image": "C:\\Windows\\System32\\net.exe", "IntegrityLevel": "High", "LogonGuid": "{b5ae2bdd-9f94-64ec-0000-002087490200}", "LogonId": "0x24987", "ParentCommandLine": "cmd.exe /c ping -n 10 127.0.0.1 > nul && net users > users.txt && net localgroup > groups.txt && ipconfig >ipinfo.txt && netstat -an >networkinfo.txt && del /F /Q C:\\Temp\\discord.exe", "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentProcessGuid": "{b5ae2bdd-8a19-64f9-0000-0010c5914800}", "ParentProcessId": "4040", "ProcessGuid": "{b5ae2bdd-8a22-64f9-0000-001057a24800}", "ProcessId": "4832", "Product": "Microsoft? Windows? Operating System", "RuleName": null, "TerminalSessionId": "1", "User": "HTBVM01\\John Doe", "UtcTime": "2023-09-07 08:30:26.925"}
```

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_winevt11.png)