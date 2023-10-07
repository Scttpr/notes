- **URL :** https://github.com/danielmiessler/SecLists
- **Description :** SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more. The goal is to enable a security tester to pull this repository onto a new testing box and have access to every type of list that may be needed.
- **Platforms :** [[Windows]], [[Linux]], [[Mac]]
- **Category :** [[Tools]]
- **Tags :** [[Password]], [[Fuzzer]], [[DNS]], [[Web]], [[Wordlist]]

## Tips

- Convert `rockyou.txt.tar.gz` to valid utf8 file:
```sh
tar xvzf rockyou.txt.tar.gz
iconv -t UTF-8 -f ISO-8859-15 rockyou.txt > rockyou_utf8.txt
```