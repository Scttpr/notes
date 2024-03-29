- **URL :** 
- **Description :** `.apmx64` files are generated by [API Monitor](http://www.rohitab.com/apimonitor), which records API call data. These files can be opened and analyzed within the tool itself. API Monitor is a software that captures and displays API calls initiated by applications and services. While its primary function is debugging and monitoring, its capability to capture API call data makes it handy for uncovering forensic artifacts.
- **Platforms :** [[Windows]]
- **Category :** [[Documentation]]
- **Tags :** [[DFIR]], [[Windows execution artifacts]]

**Registry Persistence via Run Keys**

An oft-employed strategy by adversaries to maintain unauthorized access to a compromised system is inserting an entry into the `run keys` within the Windows Registry. Let's investigate if there's any reference to the `RegOpenKeyExA` function, which accesses the designated registry key. To perform this search, simply type `RegOpenKey` into the search box, usually situated atop the API Monitor window, and press `Enter`.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_apimon6.png)

From the displayed results, it's evident that the registry key `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` corresponds to the Run registry key, which triggers the designated program upon every user login. Malicious entities often exploit this key to embed entries pointing to their backdoor, a task achievable via the registry API function `RegSetValueExA`.

To explore further, let's seek any mention of the `RegSetValueExA` function, which defines data and type for a specified value within a registry key. Engage the search box, type `RegSet`, and hit `Enter`.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_apimon7.png)

A notable observation is the `RegSetValueExA` invocation. Before diving deeper, let's familiarize ourselves with this function's documentation.

Analyzing Captured API Call Data (.apmx64)

```shell-session
LSTATUS RegSetValueExA(
  [in]           HKEY       hKey,
  [in, optional] LPCSTR     lpValueName,
                 DWORD      Reserved,
  [in]           DWORD      dwType,
  [in]           const BYTE *lpData,
  [in]           DWORD      cbData
);
```

- `hKey1` is a handle to the registry key where you want to set a registry value.
- `lpValueName` is a pointer to a null-terminated string that specifies the name of the registry value you want to set. In this case, it is named as `DiscordUpdate`.
- The `Reserved` parameter is reserved and must be zero.
- `dwType` specifies the data type of the registry value. It's likely an integer constant that represents the data type (e.g., `REG_SZ` for a string value).
- `(BYTE*)lpData` is a type cast that converts the `_lpData_` variable to a pointer to a byte (`BYTE*`). This is done to ensure that the data pointed to by `_lpData_` is treated as a byte array, which is the expected format for binary data in the Windows Registry. In our case, this is shown in the buffer view as `C:\Windows\Tasks\update.exe`.
- `cbData` is an integer that specifies the size, in bytes, of the data pointed to by `_lpData_`.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_apimon9.png)

A critical takeaway from this API call is the `lpData` parameter, which reveals the backdoor's location, `C:\Windows\Tasks\update.exe`.

**Process Injection**

To scrutinize process creation, let's search for the `CreateProcessA` function. Let's key in `CreateProcess` in the search box and press `Enter`.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_apimon5_.png)

Presented below is the syntax of the Windows API function, `CreateProcessA`.

Analyzing Captured API Call Data (.apmx64)

```shell-session
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```

An intriguing element within this API is the `lpCommandLine` parameter. It discloses the executed command line, which, in this context, is `C:\Windows\System32\comp.exe`. Notably, the `lpCommandLine` can be specified without delineating the complete executable path in the `lpApplicationName` value.

Another pivotal parameter worth noting is `dwCreationFlags`, set to `CREATE_SUSPENDED`. This indicates that the new process's primary thread starts in a suspended state and remains inactive until the `ResumeThread` function gets invoked.

The `lpCommandLine` parameter of this API call sheds light on the child process that was initiated, namely, `C:\Windows\System32\comp.exe`.

Further down we also notice process injection-related functions being utilized by `discord.exe`.

![](https://academy.hackthebox.com/storage/modules/237/disc_inj.png)

All the above are strong indicators of process injection.