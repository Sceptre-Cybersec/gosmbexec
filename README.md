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
