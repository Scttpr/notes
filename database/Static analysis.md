- **URL :** 
- **Description :** In the realm of malware analysis, we exercise a method called static analysis to scrutinize malware without necessitating its execution. This involves the meticulous investigation of malware's code, data, and structural components, serving as a vital precursor for further, more detailed analysis.
- **Platforms :** [[Windows]], [[Linux]]
- **Category :** [[Technique]]
- **Tags :** [[Cyber Threat Intelligence]], [[Reverse engineering]], [[DFIR]], [[Malware]]

## IMPHASH

`IMPHASH`, an abbreviation for "Import Hash", is a cryptographic hash calculated from the import functions of a Windows Portable Executable (PE) file. Its algorithm functions by first converting all imported function names to lowercase. Following this, the DLL names and function names are fused together and arranged in alphabetical order. Finally, an MD5 hash is generated from the resulting string. Therefore, two PE files with identical import functions, in the same sequence, will share an `IMPHASH` value.

```python
import sys
import pefile
import peutils

pe_file = sys.argv[1]
pe = pefile.PE(pe_file)
imphash = pe.get_imphash()

print(imphash)
```

## Fuzzy hashing

`Fuzzy Hashing (SSDEEP)`, also referred to as context-triggered piecewise hashing (CTPH), is a hashing technique designed to compute a hash value indicative of content similarity between two files. This technique dissects a file into smaller, fixed-size blocks and calculates a hash for each block. The resulting hash values are then consolidated to generate the final fuzzy hash.

The `SSDEEP` algorithm allocates more weight to longer sequences of common blocks, making it highly effective in identifying files that have undergone minor modifications, or are similar but not identical, such as different variations of a malicious sample.

We can find the `SSDEEP` hash of a malware in the `Details` tab of the VirusTotal results.

We can also use the `ssdeep` command to calculate the `SSDEEP` hash of a file. To check the `SSDEEP` hash of the abovementioned WannaCry malware the command would be the following.

## Section hashing

`Section hashing`, (hashing PE sections) is a powerful technique that allows analysts to identify sections of a Portable Executable (PE) file that have been modified. This can be particularly useful for identifying minor variations in malware samples, a common tactic employed by attackers to evade detection.

```python
import sys
import pefile
pe_file = sys.argv[1]
pe = pefile.PE(pe_file)
for section in pe.sections:
    print (section.Name, "MD5 hash:", section.get_hash_md5())
    print (section.Name, "SHA256 hash:", section.get_hash_sha256())
```

