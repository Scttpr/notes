- **URL :** https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table
- **Description :** The `$MFT` file, commonly referred to as the [Master File Table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table), is an integral part of the NTFS (New Technology File System) used by contemporary Windows operating systems. This file is instrumental in organizing and cataloging files and directories on an NTFS volume. Each file and directory on such a volume has a corresponding entry in the Master File Table. Think of the MFT as a comprehensive database, meticulously documenting metadata and structural details about every file and directory.
- **Platforms :** [[Windows]] 
- **Category :** [[Documentation]]
- **Tags :** [[DFIR]], [[Disk forensics]], [[NTFS]], [[MFTECmd]], [[MFT Explorer]]

#### Structure of MFT File Record

Every file or directory on an NTFS volume is symbolized by a record in the MFT. These records adhere to a structured format, brimming with attributes and details about the associated file or directory. Grasping the MFT's structure is pivotal for tasks like forensic analysis, system management, and data recovery in Windows ecosystems. It equips forensic experts to pinpoint which attributes are brimming with intriguing insights.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_mft_str1.png)

Here's a snapshot of the components:

- `File Record Header`: Contains metadata about the file record itself. Includes fields like signature, sequence number, and other administrative data.
- `Standard Information Attribute Header`: Stores standard file metadata such as timestamps, file attributes, and security identifiers.
- `File Name Attribute Header`: Contains information about the filename, including its length, namespace, and Unicode characters.
- `Data Attribute Header`: Describes the file data attribute, which can be either `resident` (stored within the MFT record) or `non-resident` (stored in external clusters).
    - `File Data (File content)`: This section holds the actual file data, which can be the file's content or references to non-resident data clusters. For small files (less than 512 bytes), the data might be stored within the MFT record (`resident`). For larger files, it references `non-resident` data clusters on the disk. We'll see an example of this later on.
- `Additional Attributes (optional)`: NTFS supports various additional attributes, such as security descriptors (SD), object IDs (OID), volume name (VOLNAME), index information, and more.

These attributes can vary depending on the file's characteristics. We can see the common type of information which is stored inside these header and attributes in the image below.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_mft_str2.png)

#### File Record Header

Contains metadata about the file record itself. Includes fields like signature, sequence number, and other administrative data.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_mft_str3.png)

The file record begins with a header that contains metadata about the file record itself. This header typically includes the following information:

- `Signature`: A four-byte signature, usually "FILE" or "BAAD," indicating whether the record is in use or has been deallocated.
- `Offset to Update Sequence Array`: An offset to the Update Sequence Array (USA) that helps maintain the integrity of the record during updates.
- `Size of Update Sequence Array`: The size of the Update Sequence Array in words.
- `Log File Sequence Number`: A number that identifies the last update to the file record.
- `Sequence Number`: A number identifying the file record. The MFT records are numbered sequentially, starting from 0.
- `Hard Link Count`: The number of hard links to the file. This indicates how many directory entries point to this file record.
- `Offset to First Attribute`: An offset to the first attribute in the file record.

When we sift through the MFT file using `MFTECmd` and extract details about a record, the information from the file record is presented as depicted in the subsequent screenshot.

File Record Header

```powershell-session
PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6> .\MFTECmd.exe -f 'C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT' --de 27142
MFTECmd version 1.2.2.1

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/MFTECmd

Command line: -f C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT --de 27142

Warning: Administrator privileges not found!

File type: Mft

Processed C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT in 3.2444 seconds

C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT: FILE records found: 93,615 (Free records: 287) File size: 91.8MB


Dumping details for file record with key 00006A06-00000005

Entry-seq #: 0x6A06-0x5, Offset: 0x1A81800, Flags: InUse, Log seq #: 0xCC64595, Base Record entry-seq: 0x0-0x0
Reference count: 0x1, FixUp Data Expected: 03-00, FixUp Data Actual: 6F-65 | 00-00 (FixUp OK: True)

**** STANDARD INFO ****
  Attribute #: 0x0, Size: 0x60, Content size: 0x48, Name size: 0x0, ContentOffset 0x18. Resident: True
  Flags: Archive, Max Version: 0x0, Flags 2: None, Class Id: 0x0, Owner Id: 0x0, Security Id: 0x557, Quota charged: 0x0, Update sequence #: 0x8B8778

  Created On:         2023-09-07 08:30:26.8316176
  Modified On:        2023-09-07 08:30:26.9097759
  Record Modified On: 2023-09-07 08:30:26.9097759
  Last Accessed On:   2023-09-07 08:30:26.9097759

**** FILE NAME ****
  Attribute #: 0x2, Size: 0x70, Content size: 0x54, Name size: 0x0, ContentOffset 0x18. Resident: True

  File name: users.txt
  Flags: Archive, Name Type: DosWindows, Reparse Value: 0x0, Physical Size: 0x0, Logical Size: 0x0
  Parent Entry-seq #: 0x16947-0x2

  Created On:         2023-09-07 08:30:26.8316176
  Modified On:        2023-09-07 08:30:26.8316176
  Record Modified On: 2023-09-07 08:30:26.8316176
  Last Accessed On:   2023-09-07 08:30:26.8316176

**** DATA ****
  Attribute #: 0x1, Size: 0x150, Content size: 0x133, Name size: 0x0, ContentOffset 0x18. Resident: True

  Resident Data

  Data: 0D-0A-55-73-65-72-20-61-63-63-6F-75-6E-74-73-20-66-6F-72-20-5C-5C-48-54-42-56-4D-30-31-0D-0A-0D-0A-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-2D-0D-0A-41-64-6D-69-6E-69-73-74-72-61-74-6F-72-20-20-20-20-20-20-20-20-20-20-20-20-62-61-63-6B-67-72-6F-75-6E-64-54-61-73-6B-20-20-20-20-20-20-20-20-20-20-20-44-65-66-61-75-6C-74-41-63-63-6F-75-6E-74-20-20-20-20-20-20-20-20-20-20-20-0D-0A-47-75-65-73-74-20-20-20-20-20-20-20-20-20-20-20-20-20-20-20-20-20-20-20-20-4A-6F-68-6E-20-44-6F-65-20-20-20-20-20-20-20-20-20-20-20-20-20-20-20-20-20-57-44-41-47-55-74-69-6C-69-74-79-41-63-63-6F-75-6E-74-20-20-20-20-20-20-20-0D-0A-54-68-65-20-63-6F-6D-6D-61-6E-64-20-63-6F-6D-70-6C-65-74-65-64-20-73-75-63-63-65-73-73-66-75-6C-6C-79-2E-0D-0A-0D-0A

    ASCII:
User accounts for \\HTBVM01

-------------------------------------------------------------------------------
Administrator            backgroundTask           DefaultAccount
Guest                    John Doe                 WDAGUtilityAccount
The command completed successfully.


    UNICODE: ????????????????????????????????????????????????????????????????+++++????????+++++???????+++++????++++++++++????++++++++?????????4+++?????????????????????
```

Each attribute signifies some entry information, identified by type.

|Type|Attribute|Description|
|---|---|---|
|0x10 (16)|$STANDARD_INFORMATION|General information - flags, MAC times, owner, and security id.|
|0x20 (32)|$ATTRIBUTE_LIST|Pointers to other attributes and a list of nonresident attributes.|
|0x30 (48)|$FILE_NAME|File name - (Unicode) and outdated MAC times|
|0x40 (64)|$VOLUME_VERSION|Volume information - NTFS v1.2 only and Windows NT, no longer used|
|0x40 (64)|$OBJECT_ID|16B unique identifier - for file or directory (NTFS 3.0+; Windows 2000+)|
|0x50 (80)|$SECURITY_DESCRIPTOR|File's access control list and security properties|
|0x60 (96)|$VOLUME_NAME|Volume name|
|0x70 (112)|$VOLUME_INFORMATION|File system version and other information|
|0x80 (128)|$DATA|File contents|
|0x90 (144)|$INDEX_ROOT|Root node of an index tree|
|0xA0 (160)|$INDEX_ALLOCATION|Nodes of an index tree - with a root in $INDEX_ROOT|
|0xB0 (176)|$BITMAP|Bitmap - for the $MFT file and for indexes (directories)|
|0xC0 (192)|$SYMBOLIC_LINK|Soft link information - (NTFS v1.2 only and Windows NT)|
|0xC0 (192)|$REPARSE_POINT|Data about a reparse point - used for a soft link (NTFS 3.0+; Windows 2000+)|
|0xD0 (208)|$EA_INFORMATION|Used for backward compatibility with OS/2 applications (HPFS)|
|0xE0 (224)|$EA|Used for backward compatibility with OS/2 applications (HPFS)|
|0x100 (256)|$LOGGED_UTILITY_STREAM|Keys and other information about encrypted attributes (NTFS 3.0+; Windows 2000+)|

To demystify the structure of an NTFS MFT file record, we're harnessing the capabilities of [Active@ Disk Editor](https://www.disk-editor.org/index.html). This potent, freeware disk editing tool is available at `C:\Program Files\LSoft Technologies\Active@ Disk Editor` and facilitates the viewing and modification of raw disk data, including the Master File Table of an NTFS system. The same insights can be gleaned from other MFT parsing tools, such as `MFT Explorer`.

We can have a closer look by opening `C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT` on `Active@ Disk Editor` and then pressing `Inspect File Record`.

![](https://academy.hackthebox.com/storage/modules/237/img2.png)

![](https://academy.hackthebox.com/storage/modules/237/img3.png)

In Disk Editor, we're privy to the raw data of MFT entries. This includes a hexadecimal representation of the MFT record, complete with its header and attributes.

**Non-Resident Flag**

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_mft_str4.png)

When parsing the entry in `MFTECmd`, this is how the non-resident data header appears.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_mft_ecmd2_.png)

**Resident Flag**

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_mft_str5.png)

When parsing the entry in `MFTECmd`, this is how the resident data header appears.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_mft_ecmd3.png)

#### Zone.Identifier data in MFT File Record

The `Zone.Identifier` is a specialized file metadata attribute in the Windows OS, signifying the security zone from which a file was sourced. It's an integral part of the Windows Attachment Execution Service (AES) and is instrumental in determining how Windows processes files procured from the internet or other potentially untrusted origins.

When a file is fetched from the internet, Windows assigns it a Zone Identifier (`ZoneId`). This ZoneId, embedded in the file's metadata, signifies the source or security zone of the file's origin. For instance, internet-sourced files typically bear a `ZoneId` of `3`, denoting the Internet Zone.

For instance, we downloaded various tools inside the `C:\Users\johndoe\Downloads` directory of this section's target. Post-download, a `ZoneID` replete with the Zone.Identifier (i.e., the source URL) has been assigned to them.

Zone.Identifier data in MFT File Record

```powershell-session
PS C:\Users\johndoe\Downloads> Get-Item * -Stream Zone.Identifier -ErrorAction SilentlyContinue


PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\johndoe\Downloads\Autoruns.zip:Zone.Identifier
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\johndoe\Downloads
PSChildName   : Autoruns.zip:Zone.Identifier
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\johndoe\Downloads\Autoruns.zip
Stream        : Zone.Identifier
Length        : 130

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\johndoe\Downloads\chainsaw_all_platforms+rules+examples.
                zip:Zone.Identifier
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\johndoe\Downloads
PSChildName   : chainsaw_all_platforms+rules+examples.zip:Zone.Identifier
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\johndoe\Downloads\chainsaw_all_platforms+rules+examples.zip
Stream        : Zone.Identifier
Length        : 679

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\johndoe\Downloads\disable-defender.ps1:Zone.Identifier
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\johndoe\Downloads
PSChildName   : disable-defender.ps1:Zone.Identifier
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\johndoe\Downloads\disable-defender.ps1
Stream        : Zone.Identifier
Length        : 55

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\johndoe\Downloads\USN-Journal-Parser-master.zip:Zone.Ide
                ntifier
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\johndoe\Downloads
PSChildName   : USN-Journal-Parser-master.zip:Zone.Identifier
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\johndoe\Downloads\USN-Journal-Parser-master.zip
Stream        : Zone.Identifier
Length        : 187

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\johndoe\Downloads\volatility3-develop.zip:Zone.Identifie
                r
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\johndoe\Downloads
PSChildName   : volatility3-develop.zip:Zone.Identifier
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\johndoe\Downloads\volatility3-develop.zip
Stream        : Zone.Identifier
Length        : 184
```

To unveil the content of a `Zone.Identifier` for a file, the following command can be executed in PowerShell.

Zone.Identifier data in MFT File Record

```powershell-session
PS C:\Users\johndoe\Downloads> Get-Content * -Stream Zone.Identifier -ErrorAction SilentlyContinue
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://learn.microsoft.com/
HostUrl=https://download.sysinternals.com/files/Autoruns.zip
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://github.com/WithSecureLabs/chainsaw/releases
HostUrl=https://objects.githubusercontent.com/github-production-release-asset-2e65be/395658506/222c726c-0fe8-4a13-82c4-a4c9a45875c6?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230813%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230813T181953Z&X-Amz-Expires=300&X-Amz-Signature=0968cc87b63f171b60eb525362c11cb6463ac5681db50dbb7807cc5384fcb771&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=395658506&response-content-disposition=attachment%3B%20filename%3Dchainsaw_all_platforms%2Brules%2Bexamples.zip&response-content-type=application%2Foctet-stream
[ZoneTransfer]
ZoneId=3
HostUrl=https://github.com/
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://github.com/PoorBillionaire/USN-Journal-Parser
HostUrl=https://codeload.github.com/PoorBillionaire/USN-Journal-Parser/zip/refs/heads/master
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://github.com/volatilityfoundation/volatility3
HostUrl=https://codeload.github.com/volatilityfoundation/volatility3/zip/refs/heads/develop
```

One of the security mechanisms, known as the `Mark of the Web` (`MotW`), hinges on the Zone Identifier. Here, the MotW marker differentiates files sourced from the internet or other potentially dubious sources from those originating from trusted or local contexts. It's frequently employed to bolster the security of applications like Microsoft Word. When an app, say Microsoft Word, opens a file bearing a MotW, it can institute specific security measures based on the MotW's presence. For instance, a Word document with a MotW might be launched in `Protected View`, a restricted mode that isolates the document from the broader system, mitigating potential security threats.

While its primary function is to bolster security for files downloaded from the web, forensic analysts can harness it for investigative pursuits. By scrutinizing this attribute, they can ascertain the file's download method. See an example below.

![](https://academy.hackthebox.com/storage/modules/237/img4.png)

#### Analyzing with Timeline Explorer

`Timeline Explorer` is another digital forensic tool developed by Eric Zimmerman which is used to assist forensic analysts and investigators in creating and analyzing timeline artifacts from various sources. Timeline artifacts provide a chronological view of system events and activities, making it easier to reconstruct a sequence of events during an investigation. We can filter timeline data based on specific criteria, such as date and time ranges, event types, keywords, and more. This feature helps focus the investigation on relevant information.

This arrangement of different events following one after another in time is really useful to create a story or timeline about what happened before and after specific events. This sequencing of events helps establish a timeline of activities on a system.

Loading a converted CSV file into Timeline Explorer is a straightforward process. Timeline Explorer is designed to work with timeline data, including CSV files that contain timestamped events or activities. To load the event data csv file into the Timeline Explorer, we can launch Timeline Explorer, and simply drag and drop from its location (e.g., our KAPE analysis directory) onto the Timeline Explorer window.

Once ingested, Timeline Explorer will process and display the data. The duration of this process hinges on the file's size.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_winevt8.png)

We will see the timeline populated with the events from the CSV file in chronological order. With the timeline data now loaded, we can explore and analyze the events using the various features provided by Timeline Explorer. We can zoom in on specific time ranges, filter events, search for keywords, and correlate related activities.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_winevt9.png)

We will provide multiple examples of using Timeline Explorer in this section.