# CheckNessusAuthScan

CheckNessusAuthScan is a lightweight PowerShell tool that helps prepare standalone Windows systems for successful authenticated Nessus scans.

It verifies the most common local requirements for credentialed scanning, presents a guided console workflow, optionally applies only the required changes, logs what was changed, and restores the original state afterwards.

> **Important:** test this on non-production systems first.

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

That means others may use, study, modify, and redistribute the software under the terms of the GPL.

## What the script does

The script helps with authenticated Nessus scanning on standalone Windows systems by:

- letting the operator select which local administrator account will be used for scanning
- letting the operator select which network interface will be used for the scan
- checking the main requirements for authenticated Nessus scans
- clearly showing which requirements pass and fail
- summarizing which changes would be required
- applying only the required temporary changes after operator confirmation
- storing the previous state before changes are applied
- restoring the previous state after the scan is complete
- supporting a restore-only mode if restoration must be retried later

## What the script checks

The script verifies:

- the selected administrator account for scanning
- Windows Firewall profile state and inbound policy
- File and Printer Sharing binding on the selected interface
- RemoteRegistry service status and startup type
- `LocalAccountTokenFilterPolicy`
- the presence of administrative shares such as `ADMIN$`, `C$`, and `IPC$`
- whether administrative shares are automatically recreated after reboot

## What the script may change temporarily

Depending on the current system state and the choices made by the operator, the script may temporarily:

- disable Windows Firewall profiles and allow inbound connections
- enable and start the RemoteRegistry service
- set `LocalAccountTokenFilterPolicy` to `1`
- enable File and Printer Sharing on the selected interface
- enable automatic administrative shares
- create a temporary local administrator account (`Check`)
- temporarily enable the built-in Administrator account, if explicitly selected by the operator

## Restore behavior

When changes are actually applied, the script saves the original state and restores the previous configuration afterwards.

The script avoids keeping stale restore state when the operator chooses **not** to apply changes.

If needed, the previous state can also be restored later using restore-only mode.

## Versions

### PowerShell version

The PowerShell version is the lightweight, transparent version intended for engineers, FAT/SAT activities, and situations where a script-based workflow is preferred.

### .NET GUI version

A separate .NET GUI version is also available for users who prefer a more guided Windows interface.

Website:
https://secudea.be/tools/nessus-auth-scanning-tool/

## Usage

### Recommended

Run the batch file so the script starts elevated:

```powershell
CheckNessusAuthScan.bat
```

### Direct PowerShell execution

You can also run the script directly:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\CheckNessusAuthScan.ps1
```

## Command-line options

### Restore-only

Restores the previously saved state without running the readiness checks again:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\CheckNessusAuthScan.ps1 -RestoreOnly
```

### ForceRestore

If a previous restore session exists, the script normally asks whether you want to restore it first. Use `-ForceRestore` to continue without that prompt:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\CheckNessusAuthScan.ps1 -ForceRestore
```

## Files and paths used

The script stores working data under:

```text
%ProgramData%\CheckNessusAuth
```

### Session file

Used to store the previous system state for restoration:

```text
%ProgramData%\CheckNessusAuth\session.json
```

### Log files

Used to log readiness checks, applied changes, and restore actions:

```text
%ProgramData%\CheckNessusAuth\Logs
```

## Typical workflow

1. Start the script as administrator
2. Select the administrator account to use for scanning
3. Select the network interface that will be used
4. Review the readiness results
5. Review the summary of required changes
6. Confirm whether the tool may apply the temporary changes
7. Perform the authenticated Nessus scan
8. Press Enter when the scan is complete
9. The script restores the previous state

## Console interface

The current script provides a cleaner console workflow with:

- titled sections
- numbered menus
- PASS/FAIL/INFO status lines
- a readiness summary
- a restore summary

Typical output includes:

- selected account
- selected interface
- firewall status per profile
- remote registry status
- UAC policy status
- administrative share status
- actions that will be taken
- restore step results

## Screenshots

Create a `docs/screenshots/` folder and add screenshots such as:

- `account-selection.png`
- `readiness-summary.png`
- `restore-phase.png`
- `gui-main-window.png`

Then reference them like this:

```markdown
![Account selection](docs/screenshots/account-selection.png)
![Readiness summary](docs/screenshots/readiness-summary.png)
![Restore phase](docs/screenshots/restore-phase.png)
![GUI main window](docs/screenshots/gui-main-window.png)
```

## Notes

- This tool is intended to help prepare standalone systems for successful authenticated Nessus scans.
- It is not meant as a permanent hardening or baseline configuration tool.
- Always validate the selected account and interface before applying changes.
- Always test first on non-production systems.

## Related links

- Project website: https://secudea.be/tools/nessus-auth-scanning-tool/
- Tenable credentialed checks documentation: https://docs.tenable.com/nessus/Content/NessusCredentialedChecks.htm

## License

GPL-3.0
