# NikkeTrace

Checks Windows for known traces of the NIKKE launcher incident.

NikkeTrace is a community tool for Windows 10/11 with Windows PowerShell 5.1. The interface defaults to English; French is also available. No Python installation is needed to run the tool.

## Run

1. Download `nikke-trace-v3.0.zip` from the [latest release](https://github.com/lolerki/nikke-trace/releases/latest).
2. Extract the ZIP, then double-click `NikkeTrace.cmd` on your Windows PC.
3. Press Enter for English, or choose `2` for French.
4. Disconnect the PC from the Internet and close the game, launcher and browsers, including tray icons near the clock.
5. Choose **1 — Full check and guided cleanup**. It runs all nine check groups together, even if the game or launcher has already been removed. Do not reinstall the game to run the check.
6. Read the result and accept or decline the proposed cleanup. The report is saved before you are asked. Press **R** at the confirmation prompt if you want to read it first.

The normal route explains current traces, historical traces, completed checks, incomplete checks and confirmed actions in plain language. Technical names and paths are available through **D — Details** and **R — Report**. Advanced checks and optional website blocking remain under **A — Advanced options**.

Run it as your usual Windows user. Administrator access is requested only if you approve adding missing rules to the system hosts file. No code is downloaded when the tool runs.

## What it does

- Checks known launcher log and cache markers, browser locations, registry entries, temporary files, and selected local process/network indicators.
- Supports Chrome, Edge, Firefox, Brave, Opera and Vivaldi, with an option to specify a custom profile location.
- Separates current artifacts from historical exposure. Green requires completed checks with no known traces; incomplete checks cannot produce a green negative result. No result certifies that the PC is clean.
- Offers one guided cleanup with consent, integrating recognized artifacts, launcher cache reset and optional recoverable installation removal. It then checks again and reports confirmed actions, failures and remaining traces.
- Can request normal browser closure after confirmation. It never force-kills browsers.
- Offers recoverable removal of a verified NIKKE installation folder by renaming it. This is not a complete Windows uninstall or a promise to remove every residual file.
- Provides password and offline antivirus guidance. It does not start an antivirus scan or reboot the PC.

Launcher cache checks cover the standard, HMT and Google Play Games variants. They inspect selected JavaScript caches, local network-state files, known HSTS domain hashes, and LevelDB storage, including Snappy-compressed tables and shared keys. Reads, decompression and traversal have size limits; unreadable, unsupported or malformed files are recorded as incomplete checks.

The launcher's shared CEF sign-in profile is checked for the same indicators. Browser credential databases are not inspected. A domain reference is reported as a historical trace, not as proof that the malware agent executed.

Uncertain files and registry entries are left in place. Automatic DLL quarantine is restricted to the recognized Chrome path; a helper folder or filename alone does not authorize deletion. The legitimate Windows HKLM CLSID is not removed.

## Guided cleanup and restart

There is no separate cache menu. Guided cleanup offers the existing NIKKE caches alongside other eligible actions. A normal cache can be reset as a precaution even if no malicious trace was found; its presence alone is not a sign of infection. If saving the report fails, nothing is changed.

When a recognized malicious startup reference must be removed, cleanup pauses after backing it up and removing it. **Save your work, restart Windows, run the same file again and choose the full check.** NikkeTrace checks that Windows has restarted, performs a fresh scan and asks for consent again before continuing with suspicious files and cache. Running it again without restarting cannot bypass this step.

A small checkpoint is stored privately under the current user's local app data. It contains a boot identifier and user SID, not executable commands or an automatic cleanup plan. Nothing is added to Windows startup, and NikkeTrace never restarts the PC itself. A missing boot identifier or invalid checkpoint stops continuation.

Recognized file quarantine is recoverable. Launcher cache deletion is permanent and is explicitly included in the confirmation. Installation removal, when an installation is confirmed, has its own consent and keeps a recoverable renamed copy.

After you agree, the game and launcher must be closed. Only these folders under the current Windows user's `%APPDATA%` can be deleted:

```text
nikke_launcher\tbs_cache
nikke_launcher_hmt\tbs_cache
nikke_launcher_google\tbs_cache
```

Deletion is permanent. It may sign you out of the launcher and reset its settings; the launcher normally recreates its cache. The report preserves detected indicators, not a backup of the cache contents. Do not restart a suspect launcher just to regenerate the cache.

The shared `%LOCALAPPDATA%\CEF\User Data` folder, browser profiles and other application folders are excluded from cache deletion. Redirected paths, junctions and symbolic links are rejected. After deletion, the tool checks again and reports remaining traces or incomplete checks; retained shared-profile traces remain visible for review.

## Optional domain blocking

**Advanced options → Block reported websites** displays the domains and missing rules before asking for consent:

```text
insightjs.com
analytics.insightjs.com
insightjs.org
```

The tool reads the existing hosts file first. It recognizes IPv4 and IPv6 blocking entries, including several domains on one line, and adds only missing rules. If all rules are present, it confirms this without writing or asking for administrator access.

Other entries are preserved. A conflicting existing mapping stops the update. Before appending, the tool creates a byte-for-byte backup alongside hosts named `hosts.NIKKE-backup-<id>`. It then reads the file back to verify the result. An error or an unreadable result is never reported as successful blocking.

This blocks only the listed names through the Windows hosts mechanism. Applications can bypass that mechanism, direct IP connections are not blocked, and existing connections may remain open. Domain blocking does not remove malware or secure exposed accounts.

## Protect your accounts

Even if no traces are found, use a clean device to change passwords saved or used on the potentially exposed PC, and any passwords reused elsewhere. Start with email and your password manager, then important accounts such as Google/Microsoft, Discord and NIKKE. Revoke existing sessions and enable two-factor authentication. If a password vault was unlocked, also replace the credentials it contained.

## Privacy and limits

The tool has no telemetry or automatic uploads. It does not extract passwords, cookies or authentication tokens. Checks inspect known markers without copying entire sensitive log lines into the report.

Reports and recovery records stay on your PC. Reports are saved under `%LOCALAPPDATA%\NIKKE-Assistance\Reports` and start with a readable summary before the technical details. They can contain your Windows username in file paths: review and redact them before sharing. This repository contains no real user reports, quarantine contents or personal machine configuration.

This is a targeted incident checker, not an antivirus or an official SHIFT UP/Level Infinite product. Other Windows accounts, unknown variants and custom locations you have not provided may not be covered. Removing traces cannot undo earlier credential theft.

## Source and build

`NikkeTrace.ps1` is the readable source. `NikkeTrace.cmd` contains that same source and temporarily extracts it to run with Windows PowerShell. The temporary script is removed on exit; no permanent execution policy change is made.

The cache reader and guarded deletion helper are embedded C# compiled locally by Windows PowerShell. No external library is downloaded. If local policy prevents compilation, the cache check cannot complete and cache deletion is not confirmed.

To rebuild the single-file launcher and player ZIP with Python 3:

```sh
python build.py
```

The ZIP in `dist/` contains only `NikkeTrace.cmd`. Players do not need the source, tests or build script.

Run the regression checks on Windows without administrator privileges:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Source.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Hosts.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Cache.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Workflow.ps1
```

Tests use temporary fixtures and mocked operations. They do not edit the system hosts file, request UAC, launch an antivirus or close real browsers.

## License

MIT — see [LICENSE](LICENSE). The single-file player launcher includes the same notice.
