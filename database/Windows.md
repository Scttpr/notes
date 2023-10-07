- **URL :** 
- **Description :** 
- **Platforms :** 
- **Category :** 
- **Tags :** 

## Execution artifacts

`Windows execution artifacts` refer to the traces and evidence left behind on a Windows operating system when programs and processes are executed. These artifacts provide valuable insights into the execution of applications, scripts, and other software components, which can be crucial in digital forensics investigations, incident response, and cybersecurity analysis. By examining execution artifacts, investigators can reconstruct timelines, identify malicious activities, and establish patterns of behavior. Here are some common types of Windows execution artifacts:

- `Prefetch Files`: Windows maintains a prefetch folder that contains metadata about the execution of various applications. Prefetch files record information such as file paths, execution counts, and timestamps of when applications were run. Analyzing prefetch files can reveal a history of executed programs and the order in which they were run.
- `Shimcache`: Shimcache is a Windows mechanism that logs information about program execution to assist with compatibility and performance optimizations. It records details such as file paths, execution timestamps, and flags indicating whether a program was executed. Shimcache can help investigators identify recently executed programs and their associated files.
- `Amcache`: Amcache is a database introduced in Windows 8 that stores information about installed applications and executables. It includes details like file paths, sizes, digital signatures, and timestamps of when applications were last executed. Analyzing the Amcache can provide insights into program execution history and identify potentially suspicious or unauthorized software.
- `UserAssist`: UserAssist is a registry key that maintains information about programs executed by users. It records details such as application names, execution counts, and timestamps. Analyzing UserAssist artifacts can reveal a history of executed applications and user activity.
- `RunMRU Lists`: The RunMRU (Most Recently Used) lists in the Windows Registry store information about recently executed programs from various locations, such as the `Run` and `RunOnce` keys. These lists can indicate which programs were run, when they were executed, and potentially reveal user activity.
- `Jump Lists`: Jump Lists store information about recently accessed files, folders, and tasks associated with specific applications. They can provide insights into user activities and recently used files.
- `Shortcut (LNK) Files`: Shortcut files can contain information about the target executable, file paths, timestamps, and user interactions. Analyzing LNK files can reveal details about executed programs and the context in which they were run.
- `Recent Items`: The Recent Items folder maintains a list of recently opened files. It can provide information about recently accessed documents and user activity.
- `Windows Event Logs`: Various Windows event logs, such as the Security, Application, and System logs, record events related to program execution, including process creation and termination, application crashes, and more.

|Artifact|Location/Registry Key|Data Stored|
|---|---|---|
|Prefetch Files|C:\Windows\Prefetch|Metadata about executed applications (file paths, timestamps, execution count)|
|Shimcache|Registry: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache|Program execution details (file paths, timestamps, flags)|
|Amcache|C:\Windows\AppCompat\Programs\Amcache.hve (Binary Registry Hive)|Application details (file paths, sizes, digital signatures, timestamps)|
|UserAssist|Registry: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist|Executed program details (application names, execution counts, timestamps)|
|RunMRU Lists|Registry: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU|Recently executed programs and their command lines|
|Jump Lists|User-specific folders (e.g., %AppData%\Microsoft\Windows\Recent)|Recently accessed files, folders, and tasks associated with applications|
|Shortcut (LNK) Files|Various locations (e.g., Desktop, Start Menu)|Target executable, file paths, timestamps, user interactions|
|Recent Items|User-specific folders (e.g., %AppData%\Microsoft\Windows\Recent)|Recently accessed files|
|Windows Event Logs|C:\Windows\System32\winevt\Logs|Various event logs containing process creation, termination, and other events|

## Windows Persistence Artifacts

Windows persistence refers to the techniques and mechanisms used by attackers to ensure their unauthorized presence and control over a compromised system, allowing them to maintain access and control even after initial intrusion. These persistence methods exploit various system components, such as registry keys, startup processes, scheduled tasks, and services, enabling malicious actors to withstand reboots and security measures while continuing to carry out their objectives undetected.

**Registry**

The Windows `Registry` acts as a crucial database, storing critical system settings for the Windows OS. This encompasses configurations for devices, security, services, and even the storage of user account security configurations in the Security Accounts Manager (`SAM`). Given its significance, it's no surprise that adversaries often target the Windows Registry for establishing persistence. Therefore, it's essential to routinely inspect Registry autorun keys.

Example of `Autorun` keys used for persistence:

- **`Run/RunOnce Keys`**
    - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
    - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
    - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\
- **`Keys used by WinLogon Process`**
    - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
- **`Startup Keys`**
    - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
    - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User

**Schtasks**

Windows provides a feature allowing programs to schedule specific tasks. These tasks reside in `C:\Windows\System32\Tasks`, with each one saved as an XML file. This file details the creator, the task's timing or trigger, and the path to the command or program set to run. To scrutinize scheduled tasks, we should navigate to `C:\Windows\System32\Tasks` and examine the XML files' content.

**Services**

`Services` in Windows are pivotal for maintaining processes on a system, enabling software components to operate in the background without user intervention. Malicious actors often tamper with or craft rogue services to ensure persistence and retain unauthorized access. The registry location to keep an eye on is: `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services`.