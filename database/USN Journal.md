- **URL :** 
- **Description :** `USN`, or `Update Sequence Number`, is a vital component of the NTFS file system in Windows. The USN Journal is essentially a change journal feature that meticulously logs alterations to files and directories on an NTFS volume.
- **Platforms :** [[Windows]]
- **Category :** [[Documentation]]
- **Tags :** [[DFIR]], [[Disk forensics]], [[NTFS]]

#### Analyzing the USN Journal Using MFTECmd

We previously utilized `MFTECmd`, one of Eric Zimmerman's tools, to parse the MFT file. While its primary focus is the MFT, MFTECmd can also be instrumental in analyzing the USN Journal. This is because entries in the USN Journal often allude to modifications to files and directories that are documented in the MFT. Hence, we'll employ this tool to dissect the USN Journal.

To facilitate the analysis of the USN Journal using `MFTECmd`, execute a command akin to the one below:

Analyzing the USN Journal Using MFTECmd

```powershell-session
PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6> .\MFTECmd.exe -f 'C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$Extend\$J' --csv C:\Users\johndoe\Desktop\forensic_data\mft_analysis\ --csvf MFT-J.csv
MFTECmd version 1.2.2.1

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/MFTECmd

Command line: -f C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$Extend\$J --csv C:\Users\johndoe\Desktop\forensic_data\mft_analysis\ --csvf MFT-J.csv

Warning: Administrator privileges not found!

File type: UsnJournal


Processed C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$Extend\$J in 0.1675 seconds

Usn entries found in C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$Extend\$J: 89,704
        CSV output will be saved to C:\Users\johndoe\Desktop\forensic_data\mft_analysis\MFT-J.csv
```

The resultant output file is saved as `MFT-J.csv` inside the `C:\Users\johndoe\Desktop\forensic_data\mft_analysis` directory. Let's import it into `Timeline Explorer` (available at `C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\TimelineExplorer`).

**Note**: Please remove the filter on the Entry Number to see the whole picture.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_usn2.png)

Upon inspection, we can discern a chronologically ordered timeline of events. Notably, the entry for `uninstall.exe` is evident.

By applying a filter on the Entry Number `93866`, which corresponds to the `Entry ID` for `uninstall.exe`, we can glean the nature of modifications executed on this specific file.

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_usn3.png)

The file extension, `.crdownload`, is indicative of a partially downloaded file. This type of file is typically generated when downloading content via browsers like Microsoft Edge, Google Chrome, or Chromium. This revelation is intriguing. If the file was downloaded via a browser, it's plausible that the `Zone.Identifier` could unveil the source IP/domain of its origin.

To investigate this assumption we should:

1. Create a CSV file for `C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT` using `MFTECmd` as we did for `C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$Extend\$J`.
2. Import the $MFT-related CSV into `Timeline Explorer`.
3. Apply a filter on the entry Number `93866`.

Analyzing the USN Journal Using MFTECmd

```powershell-session
PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6> .\MFTECmd.exe -f 'C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT' --csv C:\Users\johndoe\Desktop\forensic_data\mft_analysis\ --csvf MFT.csv
MFTECmd version 1.2.2.1

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/MFTECmd

Command line: -f C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT --csv C:\Users\johndoe\Desktop\forensic_data\mft_analysis\ --csvf MFT.csv

Warning: Administrator privileges not found!

File type: Mft

Processed C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT in 3.5882 seconds

C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT: FILE records found: 93,615 (Free records: 287) File size: 91.8MB
        CSV output will be saved to C:\Users\johndoe\Desktop\forensic_data\mft_analysis\MFT.csv
```

![](https://academy.hackthebox.com/storage/modules/237/win_dfir_mft_ecmd5_.png)