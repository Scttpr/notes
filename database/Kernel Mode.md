- **URL :** 
- **Description :** Kernel mode is a highly privileged mode where the Windows kernel runs. The kernel has unrestricted access to system resources, hardware, and critical functions. It provides core operating system services, manages system resources, and enforces security and stability. Device drivers, which facilitate communication with hardware devices, also run in kernel mode. If malware operates in kernel mode, it gains elevated control and can manipulate system behavior, conceal its presence, intercept system calls, and tamper with security mechanisms.
- **Platforms :** [[Windows]]
- **Category :** [[Documentation]]
- **Tags :** 

## Components

- `Executive`: This upper layer in kernel mode gets accessed through functions from `NTDLL.DLL`. It consists of components like the `I/O Manager`, `Object Manager`, `Security Reference Monitor`, `Process Manager`, and others, managing the core aspects of the operating system such as I/O operations, object management, security, and processes. It runs some checks first, and then passes the call to kernel, or calls the appropriate device driver to perform the requested operation.
- `Kernel`: This component manages system resources, providing low-level services like `thread scheduling`, `interrupt and exception dispatching`, and `multiprocessor synchronization`.
- `Device Drivers`: These software components enable the OS to interact with hardware devices. They serve as intermediaries, allowing the system to manage and control hardware and software resources.
- `Hardware Abstraction Layer (HAL)`: This component provides an abstraction layer between the hardware devices and the OS. It allows software developers to interact with hardware in a consistent and platform-independent manner.
- `Windowing and Graphics System (Win32k.sys)`: This subsystem is responsible for managing the graphical user interface (GUI) and rendering visual elements on the screen.