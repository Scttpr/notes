- **URL :** https://github.com/volatilityfoundation/volatility
- **Description :** Volatile memory extraction utility framework
- **Platforms :** [[Windows]], [[Linux]]
- **Category :** [[Tools]]
- **Tags :** [[DFIR]], [[RAM]], [[Memory forensics]]
- Cheatsheet : https://blog.onfvp.com/post/volatility-cheatsheet/

## Common modules

- **`pslist`**: Lists the running processes.
- **`cmdline`**: Displays process command-line arguments
- **`netscan`**: Scans for network connections and open ports.
- **`malfind`**: Scans for potentially malicious code injected into processes.
- **`handles`**: Scans for open handles
- **`svcscan`**: Lists Windows services.
- **`dlllist`**: Lists loaded DLLs (Dynamic-link Libraries) in a process.
- **`hivelist`**: Lists the registry hives in memory.

- The `psscan` plugin is used to enumerate running processes. It scans the memory pool tags associated with each process's `EPROCESS` structure. This technique can help identify processes that may have been hidden or unlinked by rootkits, as well as processes that have been terminated but have not been removed from memory yet.

