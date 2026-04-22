# CheckNessusAuthScan.ps1
#
# Can be used to perform pre-checks to allow Nessus Authenticated scans
# Requirements are from:
# https://docs.tenable.com/nessus/Content/EnableWindowsLoginsForLocalAndRemoteAudits.htm
#
# Created by Dieter Sarrazyn (dieter at secudea dot be)
#
# GPL 3.0 licensed

[CmdletBinding()]
param(
    [switch]$RestoreOnly,
    [switch]$ForceRestore
)

$ErrorActionPreference = 'Stop'

$Script:BaseFolder = Join-Path $env:ProgramData 'CheckNessusAuth'
$Script:SessionFile = Join-Path $Script:BaseFolder 'session.json'
$Script:LogFolder = Join-Path $Script:BaseFolder 'Logs'

New-Item -ItemType Directory -Path $Script:BaseFolder -Force | Out-Null
New-Item -ItemType Directory -Path $Script:LogFolder -Force | Out-Null

try {
    $Host.UI.RawUI.WindowTitle = "Check Nessus Authenticated Scan"
} catch {}

function Log-Message {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    try {
        $logDate = (Get-Date).ToString("yyyyMMdd")
        $systemName = $env:COMPUTERNAME
        $logFile = Join-Path $Script:LogFolder "$logDate $systemName CheckNessusAuthLog.txt"
        Add-Content -Path $logFile -Value ("[{0}] {1}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $Message)
    }
    catch {
        Write-Host -ForegroundColor Red "Logging failed: $($_.Exception.Message)"
    }
}

trap {
    Log-Message "UNHANDLED ERROR: $($_.Exception.Message)"
    Write-Host -ForegroundColor Red "Unhandled error: $($_.Exception.Message)"
    if ($_.ScriptStackTrace) {
        Write-Host -ForegroundColor DarkRed $_.ScriptStackTrace
        Log-Message $_.ScriptStackTrace
    }
    Write-Host ""
    Read-Host "Press Enter to close" | Out-Null
    break
}

function Write-Line {
    param(
        [int]$Length = 72,
        [string]$Color = 'DarkCyan'
    )
    Write-Host ("=" * $Length) -ForegroundColor $Color
}

function Write-Title {
    param(
        [string]$Text
    )

    Write-Host ""
    Write-Line
    Write-Host (" {0}" -f $Text) -ForegroundColor Cyan
    Write-Line
    Write-Host ""
}

function Write-Section {
    param(
        [string]$Text
    )

    Write-Host ""
    Write-Line -Color DarkGray
    Write-Host (" {0}" -f $Text) -ForegroundColor Yellow
    Write-Line -Color DarkGray
}

function Write-Info {
    param(
        [string]$Text
    )
    Write-Host "[INFO] " -ForegroundColor Cyan -NoNewline
    Write-Host $Text
}

function Write-Warn {
    param(
        [string]$Text
    )
    Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline
    Write-Host $Text
}

function Write-Status {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS','FAIL','WARN','INFO','YES','NO')]
        [string]$State,

        [string]$Detail
    )

    $color = switch ($State) {
        'PASS' { 'Green' }
        'FAIL' { 'Red' }
        'WARN' { 'Yellow' }
        'INFO' { 'Cyan' }
        'YES'  { 'Yellow' }
        'NO'   { 'Green' }
    }

    Write-Host ("{0,-52}" -f $Label) -NoNewline
    Write-Host ("[{0}]" -f $State) -ForegroundColor $color -NoNewline
    if ($Detail) {
        Write-Host ("  {0}" -f $Detail) -ForegroundColor DarkGray
    }
    else {
        Write-Host ""
    }
}

function Show-MenuItem {
    param(
        [int]$Number,
        [string]$Text,
        [string]$Color = 'White'
    )

    Write-Host ("[{0}] " -f $Number) -ForegroundColor Cyan -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

function Read-Boolean {
    param (
        [string]$Question
    )

    $response = Read-Host -Prompt $Question
    return ($response -eq 'Y' -or $response -eq 'y')
}

function Read-Integer {
    param (
        [string]$Question
    )

    $isValidInteger = $false
    $intValue = 0

    while (-not $isValidInteger) {
        $inputValue = Read-Host -Prompt $Question
        $isValidInteger = [int]::TryParse($inputValue, [ref]$intValue)

        if (-not $isValidInteger) {
            Write-Warn "Invalid input. Please enter a valid integer."
        }
    }

    return $intValue
}

function IsBuiltInAdministrator {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SID
    )

    return ($SID -match '-500$')
}

function Generate-RandomPassword {
    param(
        [int]$Length = 20
    )

    if ($Length -lt 12) {
        throw "Password length must be at least 12."
    }

    $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*_-+=".ToCharArray()
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()

    -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

function Invoke-Netsh {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Arguments
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "netsh.exe"
    $psi.Arguments = $Arguments
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $null = $process.Start()

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    if ($process.ExitCode -ne 0) {
        throw "netsh failed: $Arguments`n$stderr`n$stdout"
    }

    return $stdout
}

function CreateAdminUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    $username = "Check"

    New-LocalUser -Name $username -Password (ConvertTo-SecureString -AsPlainText $Password -Force) -AccountNeverExpires:$true -PasswordNeverExpires:$true | Out-Null
    Add-LocalGroupMember -Group "Administrators" -Member $username

    Write-Info "User $username created and added to Administrators group."
}

function Remove-TempLocalUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    $user = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    if ($user) {
        Microsoft.PowerShell.LocalAccounts\Remove-LocalUser -Name $Username
        Write-Info "User $Username removed."
    }
    else {
        Write-Info "User $Username was already absent."
    }
}

function Save-SessionState {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Session
    )

    $json = $Session | ConvertTo-Json -Depth 8
    Set-Content -Path $Script:SessionFile -Value $json -Encoding UTF8
    Log-Message "Session saved to $Script:SessionFile"
}

function Load-SessionState {
    if (-not (Test-Path $Script:SessionFile)) {
        return $null
    }

    $json = Get-Content -Path $Script:SessionFile -Raw -Encoding UTF8

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return ($json | ConvertFrom-Json -Depth 8)
    }
    else {
        return ($json | ConvertFrom-Json)
    }
}

function Remove-SessionState {
    if (Test-Path $Script:SessionFile) {
        Remove-Item -Path $Script:SessionFile -Force
        Log-Message "Session file removed."
    }
}

function Get-RegistryDwordState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        return @{
            Exists = $false
            Value  = $null
        }
    }

    return @{
        Exists = $true
        Value  = [int]$item.$Name
    }
}

function Restore-RegistryDwordState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [bool]$Exists,

        [Parameter()]
        $Value
    )

    if ($Exists) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
    }
    else {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    }
}

function Get-RegistryValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($key) {
        return $key.GetValue($Name, $null)
    }

    return $null
}

function Test-Share {
    param(
        [string]$SharePath
    )

    $share = Get-WmiObject -Class Win32_Share -Filter "Name='$SharePath'"
    return [bool]$share
}

function Show-ReadinessSummary {
    param(
        $SetFwRules,
        $SetRemoteReg,
        $SetUac,
        $SetNetworkSharing,
        $SetAdminShares,
        [string]$SelectedAccount,
        [string]$SelectedInterface
    )

    $SetFwRules = [bool]$SetFwRules
    $SetRemoteReg = [bool]$SetRemoteReg
    $SetUac = [bool]$SetUac
    $SetNetworkSharing = [bool]$SetNetworkSharing
    $SetAdminShares = [bool]$SetAdminShares

    Write-Section "Readiness Summary"

    Write-Status "Selected account" "INFO" $SelectedAccount
    Write-Status "Selected interface" "INFO" $SelectedInterface

    Write-Status "Firewall changes required" ($(if ($SetFwRules) { 'YES' } else { 'NO' }))
    Write-Status "RemoteRegistry changes required" ($(if ($SetRemoteReg) { 'YES' } else { 'NO' }))
    Write-Status "UAC policy changes required" ($(if ($SetUac) { 'YES' } else { 'NO' }))
    Write-Status "Network sharing changes required" ($(if ($SetNetworkSharing) { 'YES' } else { 'NO' }))
    Write-Status "Administrative shares changes required" ($(if ($SetAdminShares) { 'YES' } else { 'NO' }))

    $actions = New-Object System.Collections.Generic.List[string]
    if ($SetFwRules) { [void]$actions.Add("Disable firewall profiles and allow inbound connections") }
    if ($SetRemoteReg) { [void]$actions.Add("Enable and start RemoteRegistry") }
    if ($SetUac) { [void]$actions.Add("Set LocalAccountTokenFilterPolicy to 1") }
    if ($SetNetworkSharing) { [void]$actions.Add("Enable File and Printer Sharing binding on selected interface") }
    if ($SetAdminShares) { [void]$actions.Add("Enable automatic administrative shares") }

    Write-Host ""
    if ($actions.Count -eq 0) {
        Write-Host "No system changes are required." -ForegroundColor Green
    }
    else {
        Write-Host "Actions that will be taken:" -ForegroundColor Yellow
        foreach ($action in $actions) {
            Write-Host (" - {0}" -f $action) -ForegroundColor White
        }
    }
}

function Restore-PreviousState {
    param(
        [switch]$KeepSessionOnFailure
    )

    $session = Load-SessionState
    if ($null -eq $session) {
        Write-Host "No saved restore session found."
        Log-Message "Restore requested but no session file exists."
        return $false
    }

    Write-Section "Restore"
    Write-Info "Entered Restore-PreviousState"
    Log-Message "Entered Restore-PreviousState"

    $script:restoreFailed = $false

    function Invoke-RestoreStep {
        param(
            [Parameter(Mandatory = $true)]
            [string]$StepName,

            [Parameter(Mandatory = $true)]
            [scriptblock]$Action
        )

        try {
            Log-Message "Restore step started: $StepName"
            & $Action
            Log-Message "Restore step succeeded: $StepName"
            Write-Status $StepName "PASS"
        }
        catch {
            $script:restoreFailed = $true
            Log-Message "Restore step failed: $StepName - $($_.Exception.Message)"
            Write-Status $StepName "FAIL" $_.Exception.Message
        }
    }

    try {
        Log-Message "---- Restoring settings ----"

        if ($session.NetworkBindingChanged -and $session.SelectedInterfaceName) {
            Invoke-RestoreStep -StepName "Network sharing binding" -Action {
                if ([bool]$session.NetworkSharingBindingWasEnabled) {
                    Enable-NetAdapterBinding -Name $session.SelectedInterfaceName -ComponentID ms_server -ErrorAction Stop | Out-Null
                }
                else {
                    Disable-NetAdapterBinding -Name $session.SelectedInterfaceName -ComponentID ms_server -ErrorAction Stop | Out-Null
                }
            }
        }

        if ($session.SharesChanged) {
            Invoke-RestoreStep -StepName "Administrative shares registry" -Action {
                Restore-RegistryDwordState -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Exists ([bool]$session.AutoShareWksExists) -Value $session.AutoShareWksValue
                Restore-RegistryDwordState -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareServer' -Exists ([bool]$session.AutoShareServerExists) -Value $session.AutoShareServerValue
                Restart-Service -Name LanmanServer -Force -ErrorAction Stop
            }
        }

        if ($session.LatfpChanged) {
            Invoke-RestoreStep -StepName "LocalAccountTokenFilterPolicy" -Action {
                Restore-RegistryDwordState -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Exists ([bool]$session.LocalAccountTokenFilterPolicyExists) -Value $session.LocalAccountTokenFilterPolicyValue
            }
        }

        if ($session.RemoteRegistryChanged) {
            Invoke-RestoreStep -StepName "RemoteRegistry service" -Action {
                $startupType = [string]$session.RemoteRegistryStartType

                switch ($startupType) {
                    'Auto'      { Set-Service -Name RemoteRegistry -StartupType Automatic -ErrorAction Stop }
                    'Automatic' { Set-Service -Name RemoteRegistry -StartupType Automatic -ErrorAction Stop }
                    'Manual'    { Set-Service -Name RemoteRegistry -StartupType Manual -ErrorAction Stop }
                    'Disabled'  { Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction Stop }
                    default     { Set-Service -Name RemoteRegistry -StartupType Manual -ErrorAction Stop }
                }

                if ([bool]$session.RemoteRegistryWasRunning) {
                    Start-Service -Name RemoteRegistry -ErrorAction Stop
                }
                else {
                    Stop-Service -Name RemoteRegistry -Force -ErrorAction Stop
                }
            }
        }

        if ($session.FirewallChanged -and $session.FirewallProfiles) {
            Invoke-RestoreStep -StepName "Firewall profiles" -Action {
                foreach ($fw in $session.FirewallProfiles) {
                    $profileToken = switch -Regex ($fw.Name) {
                        '^Domain$'  { 'domainprofile'; break }
                        '^Private$' { 'privateprofile'; break }
                        '^Public$'  { 'publicprofile'; break }
                        default     { throw "Unknown firewall profile name '$($fw.Name)'" }
                    }

                    if ([bool]$fw.Enabled) {
                        Invoke-Netsh "advfirewall set $profileToken state on" | Out-Null
                    }
                    else {
                        Invoke-Netsh "advfirewall set $profileToken state off" | Out-Null
                    }

                    Set-NetFirewallProfile -Name $fw.Name -DefaultInboundAction $fw.DefaultInboundAction -ErrorAction Stop
                }
            }
        }

        if ($session.TempAccountCreated -and $session.TempAccountName) {
            Invoke-RestoreStep -StepName "Temporary administrator account removal" -Action {
                $tempUser = Get-LocalUser -Name $session.TempAccountName -ErrorAction SilentlyContinue
                if ($tempUser) {
                    Remove-LocalGroupMember -Group 'Administrators' -Member $session.TempAccountName -ErrorAction SilentlyContinue
                    Remove-TempLocalUser -Username $session.TempAccountName | Out-Null
                }
            }
        }

        if ($session.RealAdministratorEnabledByScript -and $session.RealAdministratorName -and (-not [bool]$session.RealAdministratorWasEnabled)) {
            Invoke-RestoreStep -StepName "Built-in Administrator disable" -Action {
                $realAdmin = Get-LocalUser -Name $session.RealAdministratorName -ErrorAction SilentlyContinue
                if ($realAdmin) {
                    Disable-LocalUser -Name $session.RealAdministratorName -ErrorAction Stop
                }
            }
        }

        if ($script:restoreFailed) {
            Write-Host ""
            Write-Warn "Restore completed with one or more errors."
            Write-Warn "Check the log file for details: $Script:LogFolder"
            Log-Message "Restore completed with errors."

            if (-not $KeepSessionOnFailure) {
                Write-Warn "The session file was kept so you can retry restore."
            }

            return $false
        }
        else {
            Log-Message "Restore completed successfully."
            Remove-SessionState
            Write-Host ""
            Write-Host "The system has been restored to its previous state." -ForegroundColor Green
            return $true
        }
    }
    catch {
        Log-Message "Restore failed fatally: $($_.Exception.Message)"
        Write-Host -ForegroundColor Red "Restore failed fatally: $($_.Exception.Message)"
        if ($_.ScriptStackTrace) {
            Write-Host -ForegroundColor DarkRed $_.ScriptStackTrace
            Log-Message $_.ScriptStackTrace
        }

        if (-not $KeepSessionOnFailure) {
            Write-Warn "The session file has been kept so you can retry."
        }

        return $false
    }
}

Write-Title "Check Nessus Authenticated Scan Readiness"

$SystemName = $env:COMPUTERNAME
$LogDate = (Get-Date).ToString("yyyy-MM-dd HH-mm-ss")
$header = "Nessus Authenticated Scan Readiness Check for $SystemName - Performed on $LogDate"
$line = "-" * $header.Length
Log-Message "$header"
Log-Message "$line`n"

$realadmin = $false
$selectedaccount = ""

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$currentUserName = $currentPrincipal.Identities.Name
$isadmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isadmin) {
    Write-Host "`nThis script has to be run as administrator - exiting now`n"
    exit 1
}

if ($RestoreOnly) {
    $restoreOk = Restore-PreviousState -KeepSessionOnFailure
    Write-Host ""
    Read-Host "Press Enter to close" | Out-Null
    if ($restoreOk) { exit 0 } else { exit 1 }
}

if ((Test-Path $Script:SessionFile) -and -not $ForceRestore) {
    Write-Warn "A previous restore session was found."
    $doRestore = Read-Boolean -Question "Do you want to restore the previous session now (Y/N)?"
    if ($doRestore) {
        $restoreOk = Restore-PreviousState -KeepSessionOnFailure
        Write-Host ""
        Read-Host "Press Enter to close" | Out-Null
        if ($restoreOk) { exit 0 } else { exit 1 }
    }
}

$administratorsGroup = Get-LocalGroupMember -Group "Administrators"
$adminsArray = @()
$index = 1

Write-Section "Select administrator account"
Show-MenuItem -Number 0 -Text "Create a new local administrator account - 'Check'" -Color Yellow

foreach ($member in $administratorsGroup) {
    $name = $member.Name
    $isRealAdmin = IsBuiltInAdministrator -SID $member.SID

    $adminsArray += [PSCustomObject]@{
        RowNumber = $index
        Name      = $name
        SID       = $member.SID
        RealAdmin = $isRealAdmin
    }

    $extra = @()
    if ($isRealAdmin) { $extra += "Real Administrator" }
    if ($name -eq $currentUserName) { $extra += "Current logged on user" }

    if ($extra.Count -gt 0) {
        Show-MenuItem -Number $index -Text ("{0} ({1})" -f $name, ($extra -join ", "))
    }
    else {
        Show-MenuItem -Number $index -Text $name
    }

    $index++
}

$selectedAccountId = Read-Integer -Question "`nSelect the administrator account you want to use for authenticated scans or select '0' to create a temporary account"
while ($selectedAccountId -lt 0 -or $selectedAccountId -gt $adminsArray.Count) {
    Write-Warn "No valid account has been selected. Please enter a valid number."
    $selectedAccountId = Read-Integer -Question "`nSelect the administrator account you want to use for authenticated scans or select '0' to create a temporary account"
}

if ($selectedAccountId -gt 0) {
    $rowNumber = [int]$selectedAccountId
    $selectedAdmin = $adminsArray | Where-Object { $_.RowNumber -eq $rowNumber } | Select-Object -First 1

    if ($null -eq $selectedAdmin) {
        throw "Failed to resolve selected administrator account."
    }

    $realadmin = [bool]$selectedAdmin.RealAdmin
    $selectedaccount = $selectedAdmin.Name
    $isadmin = $true
}
elseif ($selectedAccountId -eq 0) {
    $selectedaccount = "Check"
    $add_account = $true
    $isadmin = $true
}

Write-Host ""
Write-Status "Selected user account" "INFO" $selectedaccount
Write-Status "Account is administrator" ($(if ($isadmin) { 'PASS' } else { 'FAIL' }))
Log-Message "Selected user account: $selectedaccount"

Write-Section "Select scan interface"

$Interfaces = Get-NetIPConfiguration | ForEach-Object {
    $cfg = $_
    foreach ($ip in $cfg.AllIPAddresses) {
        if ($ip.IPAddress -notmatch '^(::1|fe80::|169\.254\.)') {
            [PSCustomObject]@{
                InterfaceIndex       = $cfg.InterfaceIndex
                InterfaceAlias       = $cfg.InterfaceAlias
                InterfaceDescription = $cfg.InterfaceDescription
                IPAddress            = $ip.IPAddress
                PrefixLength         = $ip.PrefixLength
                DeviceId             = $cfg.NetAdapter.DeviceID
            }
        }
    }
}

if (-not $Interfaces) {
    throw "No usable network interfaces were found."
}

$Interfaces | Sort-Object InterfaceIndex, IPAddress | Format-Table InterfaceIndex, InterfaceAlias, IPAddress, PrefixLength, InterfaceDescription -AutoSize

$validInterfaceIds = $Interfaces.InterfaceIndex | Sort-Object -Unique
$scanning_interface_id = Read-Integer -Question "Enter the Interface Index that will be used for the authenticated scan"

while ($validInterfaceIds -notcontains $scanning_interface_id) {
    Write-Warn "Invalid interface index selected."
    $scanning_interface_id = Read-Integer -Question "Enter the Interface Index that will be used for the authenticated scan"
}

$selectedInterface = $Interfaces | Where-Object { $_.InterfaceIndex -eq $scanning_interface_id } | Select-Object -First 1
$scanning_interface_deviceid = $selectedInterface.DeviceId

Write-Status "Selected interface" "INFO" ("{0} ({1})" -f $selectedInterface.InterfaceAlias, $selectedInterface.IPAddress)

Write-Section "Running readiness checks"

$firewallservice = Get-Service mpssvc | Select-Object Status, StartType

if ($firewallservice.Status -eq "Running") {
    Write-Status "Firewall service is not running" "FAIL"
    Log-Message "Firewall service is running - checking policies and default inbound actions..."

    $fw_policies = Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction

    foreach ($fw_policy in $fw_policies) {
        if ($fw_policy.Enabled) {
            Write-Status ("Firewall policy disabled - " + $fw_policy.Name) "FAIL"
            $set_fw_rules = $true
            Log-Message "- $($fw_policy.Name) is Enabled"
        }
        else {
            Write-Status ("Firewall policy disabled - " + $fw_policy.Name) "PASS"
            Log-Message "- $($fw_policy.Name) is Disabled"
        }
    }

    foreach ($fw_policy in $fw_policies) {
        if ($fw_policy.DefaultInboundAction -eq "Block") {
            Write-Status ("Firewall inbound allow - " + $fw_policy.Name) "FAIL"
            $set_fw_rules = $true
            Log-Message "- $($fw_policy.Name) inbound is Block"
        }
        else {
            Write-Status ("Firewall inbound allow - " + $fw_policy.Name) "PASS"
            Log-Message "- $($fw_policy.Name) inbound is Allow"
        }
    }
}
else {
    Write-Status "Firewall service is not running" "PASS"
    Log-Message "Firewall service is not running - good to go..."
}

$instance_filter = $scanning_interface_deviceid + "::ms_server"
$adapter_bindings = Get-NetAdapterBinding | Where-Object { $_.InstanceID -eq $instance_filter } | Select-Object Name, Enabled
$adapter_binding = [bool]$adapter_bindings.Enabled

if ($adapter_binding) {
    Write-Status "Network sharing enabled on selected interface" "PASS" $adapter_bindings.Name
    Log-Message "Network sharing is enabled on selected interface ($($adapter_bindings.Name))"
}
else {
    Write-Status "Network sharing enabled on selected interface" "FAIL" $adapter_bindings.Name
    Log-Message "Network sharing is NOT enabled on selected interface ($($adapter_bindings.Name))"
    $set_network_sharing = $true
}

$remoteregservice = Get-Service RemoteRegistry | Select-Object Status, StartType

if ($remoteregservice.Status -eq "Running") {
    Write-Status "Remote registry service is running" "PASS"
    Log-Message "Remote registry service is running"
}
else {
    Write-Status "Remote registry service is running" "FAIL"
    Log-Message "Remote registry service is NOT running"
    $set_remote_reg = $true
}

if ($remoteregservice.StartType -ne "Disabled") {
    Write-Status "Remote registry service startup type is not disabled" "PASS"
    Log-Message "Remote registry service startup type is not set to disabled"
}
else {
    Write-Status "Remote registry service startup type is not disabled" "FAIL"
    Log-Message "Remote registry service startup type is set to disabled"
    $set_remote_reg = $true
}

$LocalAccountTokenFilterPolicy = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy'

if ($LocalAccountTokenFilterPolicy -ne 1) {
    Write-Status "UAC LocalAccountTokenFilterPolicy set to 1" "FAIL"
    Log-Message "LocalAccountTokenFilterPolicy is not set to 1"
    $set_uac = $true
}
else {
    Write-Status "UAC LocalAccountTokenFilterPolicy set to 1" "PASS"
    Log-Message "LocalAccountTokenFilterPolicy is set to 1"
}

$isAdminShareEnabled = (Test-Share -SharePath "C$") -and (Test-Share -SharePath "ADMIN$") -and (Test-Share -SharePath "IPC$")

if ($isAdminShareEnabled) {
    Write-Status "Administrative shares are enabled" "PASS"
    Log-Message "Administrative shares are enabled"
}
else {
    Write-Status "Administrative shares are enabled" "FAIL"
    Log-Message "Administrative shares are NOT enabled"
    $set_admin_shares = $true
}

$autoShareWksState = Get-RegistryDwordState -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks'
$autoShareServerState = Get-RegistryDwordState -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareServer'

if (($autoShareWksState.Exists -and $autoShareWksState.Value -eq 0) -or
    ($autoShareServerState.Exists -and $autoShareServerState.Value -eq 0)) {
    Write-Status "Administrative shares auto-created after reboot" "FAIL"
    Log-Message "Administrative shares are not automatically recreated after reboot"
    $set_admin_shares = $true
}
else {
    Write-Status "Administrative shares auto-created after reboot" "PASS"
    Log-Message "Administrative shares are automatically recreated after reboot"
}

Show-ReadinessSummary `
    -SetFwRules ([bool]$set_fw_rules) `
    -SetRemoteReg ([bool]$set_remote_reg) `
    -SetUac ([bool]$set_uac) `
    -SetNetworkSharing ([bool]$set_network_sharing) `
    -SetAdminShares ([bool]$set_admin_shares) `
    -SelectedAccount $selectedaccount `
    -SelectedInterface ("{0} ({1})" -f $selectedInterface.InterfaceAlias, $selectedInterface.IPAddress)

$session = [ordered]@{
    MachineName                         = $env:COMPUTERNAME
    CreatedUtc                          = (Get-Date).ToUniversalTime().ToString("o")
    SelectedInterfaceName               = $selectedInterface.InterfaceAlias

    FirewallProfiles                    = @()
    RemoteRegistryStartType             = $null
    RemoteRegistryWasRunning            = $false

    LocalAccountTokenFilterPolicyExists = $false
    LocalAccountTokenFilterPolicyValue  = $null

    AutoShareWksExists                  = $false
    AutoShareWksValue                   = $null
    AutoShareServerExists               = $false
    AutoShareServerValue                = $null

    NetworkSharingBindingWasEnabled     = $false

    TempAccountCreated                  = $false
    TempAccountName                     = $null

    RealAdministratorName               = $null
    RealAdministratorWasEnabled         = $null
    RealAdministratorEnabledByScript    = $false

    FirewallChanged                     = $false
    RemoteRegistryChanged               = $false
    LatfpChanged                        = $false
    SharesChanged                       = $false
    NetworkBindingChanged               = $false
}

$session.FirewallProfiles = @(
    Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        @{
            Name                 = $_.Name
            Enabled              = [bool]$_.Enabled
            DefaultInboundAction = $_.DefaultInboundAction.ToString()
        }
    }
)

$remoteRegistryCim = Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'"
$session.RemoteRegistryStartType = [string]$remoteRegistryCim.StartMode
$session.RemoteRegistryWasRunning = ([string]$remoteRegistryCim.State -eq 'Running')

$latfpState = Get-RegistryDwordState -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy'
$session.LocalAccountTokenFilterPolicyExists = $latfpState.Exists
$session.LocalAccountTokenFilterPolicyValue = $latfpState.Value

$session.AutoShareWksExists = $autoShareWksState.Exists
$session.AutoShareWksValue = $autoShareWksState.Value
$session.AutoShareServerExists = $autoShareServerState.Exists
$session.AutoShareServerValue = $autoShareServerState.Value

$instance_filter = $scanning_interface_deviceid + "::ms_server"
$adapter_bindings = Get-NetAdapterBinding | Where-Object { $_.InstanceID -eq $instance_filter } | Select-Object Name, Enabled
$adapter_binding = [bool]$adapter_bindings.Enabled
$session.NetworkSharingBindingWasEnabled = $adapter_binding

Save-SessionState -Session $session

$make_changes = Read-Boolean -Question "`nDo you want to make the necessary changes to allow authenticated scanning (Y/N)?"
if ($make_changes) {
    $restoreAttempted = $false

    try {
        Log-Message "---- Making necessary changes to the system to allow authenticated scanning ----"
        Write-Section "Apply changes"
        Write-Info "Entering apply phase."

        if ($realadmin) {
            $accountName = $selectedaccount
            if ($selectedaccount -like "*\*") {
                $computerName, $accountName = $selectedaccount -split "\\", 2
            }

            $isEnabled = (Get-LocalUser $accountName -ErrorAction Stop).Enabled
            $session.RealAdministratorName = $accountName
            $session.RealAdministratorWasEnabled = [bool]$isEnabled
            Save-SessionState -Session $session

            $continuerealadminchangepass = $false
            $continuerealadminchangepassenable = $false

            if ($isEnabled) {
                Write-Warn "You selected to use the Real Administrator."
                $continuerealadmin = Read-Boolean -Question "Do you want to continue using the real administrator (Y/N)?"
                if (-not $continuerealadmin) {
                    throw "User aborted use of the built-in Administrator account."
                }

                $continuerealadminchangepass = Read-Boolean -Question "Do you want to change the password of the real administrator (Y/N)?"
            }
            else {
                Write-Warn "You selected to use the Real Administrator while it is disabled."
                $continuerealadminchangepassenable = Read-Boolean -Question "Do you want to continue using the real administrator, enable the account and change the password (Y/N)?"
                if (-not $continuerealadminchangepassenable) {
                    throw "User aborted use of the disabled built-in Administrator account."
                }
            }

            if ($continuerealadminchangepass) {
                $securePassword = Read-Host -Prompt "Enter the new password for the user account" -AsSecureString
                Set-LocalUser -Name $accountName -Password $securePassword
                Write-Status "Built-in Administrator password changed" "PASS"
                Log-Message "Password of $accountName has been changed."
            }

            if ($continuerealadminchangepassenable) {
                Enable-LocalUser -Name $accountName
                $session.RealAdministratorEnabledByScript = $true
                Save-SessionState -Session $session

                Log-Message "$accountName has been enabled."
                $securePassword = Read-Host -Prompt "Enter the new password for the user account" -AsSecureString
                Set-LocalUser -Name $accountName -Password $securePassword
                Write-Status "Built-in Administrator enabled" "PASS"
                Write-Status "Built-in Administrator password changed" "PASS"
                Log-Message "Password of $accountName has been changed."
            }
        }

        if ($add_account) {
            Write-Info "Adding a temporary user account ('Check') and adding it to the Administrators group..."
            $password_provided = Read-Boolean -Question "Do you want to provide a password? Select No to use a generated temporary password. (Y/N)"

            if ($password_provided) {
                $password = Read-Host -Prompt "Enter the password for the temporary user account"
            }
            else {
                $password = Generate-RandomPassword -Length 20
                Write-Host "Generated temporary password: $password" -ForegroundColor Yellow
            }

            CreateAdminUser -Password $password
            $session.TempAccountCreated = $true
            $session.TempAccountName = "Check"
            Save-SessionState -Session $session
            Write-Status "Temporary administrator account created" "PASS"
        }

        if ($set_fw_rules) {
            Write-Info "Disabling firewall and allowing all inbound connections for all profiles..."
            Invoke-Netsh "advfirewall set domainprofile state off" | Out-Null
            Invoke-Netsh "advfirewall set privateprofile state off" | Out-Null
            Invoke-Netsh "advfirewall set publicprofile state off" | Out-Null

            Set-NetFirewallProfile -Name Domain -DefaultInboundAction Allow
            Set-NetFirewallProfile -Name Private -DefaultInboundAction Allow
            Set-NetFirewallProfile -Name Public -DefaultInboundAction Allow

            $session.FirewallChanged = $true
            Save-SessionState -Session $session
            Write-Status "Firewall changes applied" "PASS"
        }

        if ($set_remote_reg) {
            Write-Info "Enabling and starting the RemoteRegistry service..."
            Set-Service -Name RemoteRegistry -StartupType Automatic
            Start-Service -Name RemoteRegistry
            $session.RemoteRegistryChanged = $true
            Save-SessionState -Session $session
            Write-Status "RemoteRegistry changes applied" "PASS"
        }

        if ($set_uac) {
            Write-Info "Setting LocalAccountTokenFilterPolicy to 1..."
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Force
            $session.LatfpChanged = $true
            Save-SessionState -Session $session
            Write-Status "UAC policy changes applied" "PASS"
        }

        if ($set_network_sharing) {
            Write-Info "Enabling the Windows network sharing binding on the interface..."
            Enable-NetAdapterBinding -Name $adapter_bindings.Name -ComponentID ms_server | Out-Null
            $session.NetworkBindingChanged = $true
            Save-SessionState -Session $session
            Write-Status "Network sharing changes applied" "PASS"
        }

        if ($set_admin_shares) {
            Write-Info "Enabling automatic administrative shares..."
            if ($autoShareWksState.Exists -and $autoShareWksState.Value -eq 0) {
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Value 1 -Force
            }
            if ($autoShareServerState.Exists -and $autoShareServerState.Value -eq 0) {
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareServer' -Value 1 -Force
            }
            Restart-Service -Name LanmanServer -Force
            $session.SharesChanged = $true
            Save-SessionState -Session $session
            Write-Status "Administrative shares changes applied" "PASS"
        }

        Write-Section "Scan phase"
        Write-Host "Perform the authenticated scan now." -ForegroundColor Yellow
        Log-Message "Apply phase complete. Waiting for operator confirmation to restore."

        Read-Host -Prompt "When the scan is complete, press Enter to restore the original state" | Out-Null

        Write-Section "Restore phase"
        Write-Info "Starting restore..."
        Log-Message "Calling Restore-PreviousState after scan prompt."
        $restoreAttempted = $true
        $restoreOk = Restore-PreviousState -KeepSessionOnFailure

        if ($restoreOk) {
            Log-Message "Restore call returned success."
            Write-Host -ForegroundColor Green "Restore completed."
        }
        else {
            Log-Message "Restore call returned failure."
            Write-Warn "Restore completed with errors. Check the log."
        }
    }
    catch {
        Log-Message "Fatal error in apply/scan flow: $($_.Exception.Message)"
        Write-Host -ForegroundColor Red "Fatal error: $($_.Exception.Message)"
        if ($_.ScriptStackTrace) {
            Write-Host -ForegroundColor DarkRed $_.ScriptStackTrace
            Log-Message $_.ScriptStackTrace
        }

        if (-not $restoreAttempted -and (Test-Path $Script:SessionFile)) {
            Write-Host ""
            Write-Warn "Attempting restore after error..."
            Log-Message "Calling Restore-PreviousState from catch block."
            $null = Restore-PreviousState -KeepSessionOnFailure
        }
    }
    finally {
        Write-Host ""
        Read-Host "Press Enter to close" | Out-Null
    }
}
else {
    Remove-SessionState
    Write-Info "No changes were made."
    Log-Message "User chose not to apply changes. Session file removed."
}