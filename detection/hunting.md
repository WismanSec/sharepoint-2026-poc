# Detection & Hunting — SharePoint `/_trust` Deserialization

Queries are written generically; adapt field names to your SIEM. Examples in a piped search-language (nPL-style) as used in the lab.

## A. The universal signature (present in EVERY variant) — start here

The web request is the only artifact common to RCE **and** the stealthy key-dump.

```
# IIS / SharePoint request logs
uri_path = "/_trust/default.aspx" AND http_method = "POST"
  AND request_body contains "wa=wsignin1.0"
  AND request_body contains "RequestSecurityTokenResponse"
```

Pivots / enrich:
- Anomalous or scripted `User-Agent` (e.g. `WindowsPowerShell/5.1...`, `python-requests`, curl).
- Response status: legitimate WS-Federation sign-in traffic to this endpoint is predominantly **HTTP 302**; exploitation returns other statuses — 200, 500, a connection reset, or 400 when AMSI blocks. Where the endpoint carries real sign-in volume, a non-302 response is anomalous. (Status alone does not confirm success — a successful run returned both 200 and a reset.)
- Unauthenticated source; bursts of 2 requests (key-dump is a 2-stage preamble+main).

## B. Process-based (RCE variants only — will MISS the key-dump)

```
event_id = 4688 AND parent_process = "w3wp.exe"
  AND process IN ("cmd.exe", "powershell.exe", "whoami.exe", "csc.exe")
```

- **Do not key solely on `w3wp → cmd → powershell`.** The `--rawcmd` variant is `w3wp → powershell` directly and evades the `WebshellLauncher.A` behavioral signature.
- Decode `powershell.exe -EncodedCommand <b64>` straight from the 4688 command line — it is base64(UTF-16LE) and **not** otherwise obfuscated: `echo <b64> | base64 -d | iconv -f utf-16le -t utf-8`

## C. Defender behavioral (cmd-tree only)

```
provider = "Microsoft-Windows-Windows Defender" AND event_id IN (1116, 1117)
  AND threat_name = "Behavior:Win32/WebshellLauncher.A"
```

⚠️ **A detection here does NOT mean the attack was stopped.** Remediation ("Remove") races the payload; the OOB beacon can complete first. On any 1116/1117 with this threat, **also** search DNS/proxy/firewall egress for the callback domain in the surrounding ±1 minute.

## D. Egress / OOB beacon

```
# DNS or proxy logs, from the SharePoint host, as the pool identity
dns_query matches "*.oast.*" OR "*.<newly-seen-domain>"
  OR outbound_http where src_host = <sharepoint> AND user = <pool identity>
```

## IOC list (this PoC; substitute real values in an investigation)

| Type | Value |
|---|---|
| URI | `POST /_trust/default.aspx` (`wa=wsignin1.0`, `wresult` with `SecurityContextToken`) |
| Defender threat (process behavior) | `Behavior:Win32/WebshellLauncher.A` (ID 2147776984), EID 1116/1117 |
| AMSI detection (if `/_trust` body-scanned) | `Exploit:Script/SpCookieExec.A` (ID 2147969862), source AMSI, HTTP 400 block |
| Process | `w3wp.exe` → `cmd.exe`/`powershell.exe` (`-EncodedCommand`) → `conhost.exe`/`whoami.exe` |
| PowerShell UA (beacon) | `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.x` |
| Persistence | machine-key theft → forged `__VIEWSTATE` (rotate keys to revoke) |

## The key-dump's telemetry footprint (AMSI-dependent)

- In the default-config farm (Defender AV): **no `4688` child, no Defender event, no beacon** — it runs in-process in `w3wp`. Detect via **A** (the `/_trust` request) + response-size anomaly.
- **AMSI request-body scanning blocks it.** If SharePoint's AMSI request-body scan covers `/_trust` (Full mode, or `/_trust/default.aspx` added as a Balanced targeted endpoint), the request is rejected `HTTP 400` before deserialization and Defender logs `Exploit:Script/SpCookieExec.A` (detection source AMSI, action Quarantine). In the default Balanced configuration `/_trust` is not scanned, so neither chain is detected at this layer. The same control blocks the RCE before any process is created. Confirm the web application's `AMSIBodyScanMode` and targeted-endpoint list.
