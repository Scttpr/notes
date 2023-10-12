- **URL :** 
- **Description :** 
- **Platforms :** *
- **Category :** [[Documentation]]
- **Tags :** [[FileSystem]], [[DFIR]], [[Disk forensics]]

#### General Rules for Timestamps in the Windows NTFS File System

The table below delineates the general rules governing how various file operations influence the timestamps within the Windows NTFS (New Technology File System).

|Operation|Modified|Accessed|Birth (Created)|
|---|---|---|---|
|File Create|Yes|Yes|Yes|
|File Modify|Yes|No|No|
|File Copy|No (Inherited)|Yes|Yes|
|File Access|No|No*|No|

1. **File Create**:
    - `Modified Timestamp (M)`: The Modified timestamp is updated to reflect the time of file creation.
    - `Accessed Timestamp (A)`: The Accessed timestamp is updated to reflect that the file was accessed at the time of creation.
    - `Birth (Created) Timestamp (b)`: The Birth timestamp is set to the time of file creation.
2. **File Modify**:
    - `Modified Timestamp (M)`: The Modified timestamp is updated to reflect the time when the file's content or attributes were last modified.
    - `Accessed Timestamp (A)`: The Accessed timestamp is not updated when the file is modified.
    - `Birth (Created) Timestamp (b)`: The Birth timestamp is not updated when the file is modified.
3. **File Copy**:
    - `Modified Timestamp (M)`: The Modified timestamp is typically not updated when a file is copied. It usually inherits the timestamp from the source file.
    - `Accessed Timestamp (A)`: The Accessed timestamp is updated to reflect that the file was accessed at the time of copying.
    - `Birth (Created) Timestamp (b)`: The Birth timestamp is updated to the time of copying, indicating when the copy was created.
4. **File Access**:
    - `Modified Timestamp (M)`: The Modified timestamp is not updated when the file is accessed.
    - `Accessed Timestamp (A)`: The Accessed timestamp is updated to reflect the time of access.
    - `Birth (Created) Timestamp (b)`: The Birth timestamp is not updated when the file is accessed.

All these timestamps reside in the `$MFT` file, located at the root of the system drive. While the `$MFT` file will be covered in greater depth later, our current focus remains on understanding these timestamps.

These timestamps are housed within the `$MFT` across two distinct attributes:
- `$STANDARD_INFORMATION`
- `$FILE_NAME`

The timestamps visible in the Windows file explorer are derived from the `$STANDARD_INFORMATION` attribute.