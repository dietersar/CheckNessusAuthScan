# CheckNessusAuthScan

CheckNessusAuthScan is a lightweight PowerShell tool that helps prepare standalone Windows systems for successful authenticated Nessus scans.

It verifies the most common local requirements for credentialed scanning, presents a guided console workflow, optionally applies only the required changes, logs what was changed, and restores the original state afterwards.

> **Important:** test this on non-production systems first.

The checks and temporary configuration steps are based on Tenable guidance for local and remote Windows audits.

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

The script now avoids keeping stale restore state when the operator chooses **not** to apply changes.

If needed, the previous state can also be restored later using restore-only mode.

## Usage

### Recommended
Run the batch file so the script starts elevated:

```powershell
CheckNessusAuthScan.bat
