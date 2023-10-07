- **URL :** 
- **Description :** 
- **Platforms :** 
- **Category :** [[Technique]]
- **Tags :** [[DFIR]]

`Memory forensics`, also known as volatile memory analysis, is a specialized branch of digital forensics that focuses on the examination and analysis of the volatile memory (RAM) of a computer or digital device. Unlike traditional digital forensics, which involves analyzing data stored on non-volatile storage media like hard drives or solid-state drives, memory forensics deals with the live state of a system at a particular moment in time.

Here are some types of data found in RAM that are valuable for incident investigation:
- `Network connections`
- `File handles and open Files`
- `Open registry keys`
- `Running processes on the system`
- `Loaded modules`
- `Loaded device drivers`
- `Command history and console sessions`
- `Kernel data structures`
- `User and credential information`
- `Malware artifacts`
- `System configuration`
- `Process memory regions`

As we discussed both in the previous section and in the `YARA & Sigma for SOC Analysts` module, when malware operates, it often leaves traces or footprints in a system's active memory. By analyzing this memory, investigators can uncover malicious processes, identify indicators of compromise, and reconstruct the malware's actions.

It should be noted that in some cases, important data or encryption keys may reside in memory. Memory forensics can help recover this data, which may be crucial for an investigation.

The following outlines a systematic approach to memory forensics, formulated to aid in in-memory investigations and drawing inspiration from [SANS](https://www.sans.org/)'s six-step memory forensics methodology.

1. `Process Identification and Verification`: Let's begin by identifying all active processes. Malicious software often masquerades as legitimate processes, sometimes with subtle name variations to avoid detection. We need to:
    - Enumerate all running processes.
    - Determine their origin within the operating system.
    - Cross-reference with known legitimate processes.
    - Highlight any discrepancies or suspicious naming conventions.
2. `Deep Dive into Process Components`: Once we've flagged potentially rogue processes, our next step is to scrutinize the associated Dynamic Link Libraries (DLLs) and handles. Malware often exploits DLLs to conceal its activities. We should:
    - Examine DLLs linked to the suspicious process.
    - Check for unauthorized or malicious DLLs.
    - Investigate any signs of DLL injection or hijacking.
3. `Network Activity Analysis`: Many malware strains, especially those that operate in stages, necessitate internet connectivity. They might beacon to Command and Control (C2) servers or exfiltrate data. To uncover these:
    - Review active and passive network connections in the system's memory.
    - Identify and document external IP addresses and associated domains.
    - Determine the nature and purpose of the communication.
        - Validate the process' legitimacy.
        - Assess if the process typically requires network communication.
        - Trace back to the parent process.
        - Evaluate its behavior and necessity.
4. `Code Injection Detection`: Advanced adversaries often employ techniques like process hollowing or utilize unmapped memory sections. To counter this, we should:
    - Use memory analysis tools to detect anomalies or signs of these techniques.
    - Identify any processes that seem to occupy unusual memory spaces or exhibit unexpected behaviors.
5. `Rootkit Discovery`: Achieving stealth and persistence is a common goal for adversaries. Rootkits, which embed deep within the OS, grant threat actors continuous, often elevated, system access while evading detection. To tackle this:
    - Scan for signs of rootkit activity or deep OS alterations.
    - Identify any processes or drivers operating at unusually high privileges or exhibiting stealth behaviors.
6. `Extraction of Suspicious Elements`: After pinpointing suspicious processes, drivers, or executables, we need to isolate them for in-depth analysis. This involves:
    - Dumping the suspicious components from memory.
    - Storing them securely for subsequent examination using specialized forensic tools.
