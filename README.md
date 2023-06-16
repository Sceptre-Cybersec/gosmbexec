[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Lifecycle:Maturing](https://img.shields.io/badge/Lifecycle-Maturing-007EC6)](https://github.com/bcgov/repomountie/blob/master/doc/lifecycle-badges.md)
# go-smbexec

Go implementation of SMB exec.

## Why does this exist?
I couldn't find any smbexec implementations that allow you to pass an NTLM hash, so I decided to make my own.

## Limitations:
- right now the maximum size of a command to execute is 4096 bytes
- doesn't support kerberos

## Credits:
All credits go to https://github.com/Kevin-Robertson/Invoke-TheHash. I got pretty much all the code from there and used ChatGpt to translate it into golang.  
I still had to do a lot of troubleshooting, but not nearly as much as if I implemented it from scratch.

## Example usage:
**Install:**
```bash
go install github.com/wadeking98/go-smbexec@latest
```

**Usage:**
```bash
go-smbexec -u Administrator -p 'Password!' -h 127.0.0.1 -d lab.local -c 'echo test C:\test.txt'
```
```bash
go-smbexec -u Administrator -hash fbdcd5041c96ddbd82224270b57f11fc -h 127.0.0.1 -d lab.local -c 'echo test C:\test.txt'
```

**Created by:**
 <a href="https://app.hackthebox.com/users/254685"><img src="http://www.hackthebox.eu/badge/image/254685" alt="Hack The Box"></a>
