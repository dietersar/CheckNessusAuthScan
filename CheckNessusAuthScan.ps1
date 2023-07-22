# Getting the current logged on user and verify whether it is a local administrator account or not
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$currentUserName = $currentPrincipal.Identities.Name
$isadmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Current used user account: " -NoNewline
Write-Host $currentUserName
Write-Host "Account is administrator: " -NoNewline

if ($isadmin)
{
    Write-Host -ForegroundColor Green "PASS"
}
else 
{
    Write-Host -ForegroundColor Red "FAIL"
}

# Getting the Interface and IP address information to identify the interface on the system that will be used for authenticated scanning

$Interfaces = Get-NetIPConfiguration | Select-object InterfaceDescription -ExpandProperty AllIPAddresses | Where-Object { $_.IPAddress -notmatch "^(::1|fe80::|169\.254\.\d{1,3}\.\d{1,3})" } | Select ifIndex, IPAddress, PrefixLength, InterfaceAlias  | Format-Table *

Write-Output $Interfaces
$scanning_interface_id = Read-Host -Prompt "Enter the Interface Index that will be used for the authenticated scan"
$scanning_interface = Get-NetIPConfiguration | Where-Object { $_.InterfaceIndex -eq $scanning_interface_id }
$scanning_interface_deviceid = $scanning_interface.NetAdapter.DeviceID

Write-Host "`n==> Verifying the firewall policies and Default Inbound Actions that are configured on the system. For each profile, either one of the two PASS is ok`n"

$fw_policies = Get-NetFirewallProfile -PolicyStore ActiveStore | select Name, Enabled, DefaultInboundAction

Write-Host "Firewall Policy is set to Disabled: "
Foreach ($fw_policy in $fw_policies)
{
    Write-Host "- $($fw_policy.Name):`t" -NoNewline
    if ($fw_policy.Enabled)
    {
        Write-Host -ForegroundColor Red "FAIL"
    }
    else 
    {
        Write-Host -ForegroundColor Green "PASS"
    }
}
Write-Host "Firewall DefaultInboundAction is set to Allow: "
Foreach ($fw_policy in $fw_policies)
{
    Write-Host "- $($fw_policy.Name):`t" -NoNewline
    if ($fw_policy.DefaultInboundAction -eq "Block")
    {
        Write-Host -ForegroundColor Red "FAIL"
    }
    else 
    {
        Write-Host -ForegroundColor Green "PASS"
    }
}

Write-Host "`n==> Verifying if the network sharing service is installed on the selected interface`n"

$instance_filter = $scanning_interface_deviceid + "::ms_server"
$adapter_bindings = Get-NetAdapterBinding | Where-Object { $_.InstanceID -eq $instance_filter } | Select-Object Enabled
$adapter_binding = $adapter_bindings.Enabled

Write-Host "Network sharing enabled on selected interface: " -NoNewline
if ($adapter_binding)
{
    Write-Host -ForegroundColor Green "PASS"
}
else 
{
    Write-Host -ForegroundColor Red "FAIL"
}

Write-Host "`n==> Verifying if the remote registry service is started and what its startup type is set to`n"

$remoteregservice = Get-Service RemoteRegistry | Select Status, StartType
Write-Host "Remote registry service is running: " -NoNewline
if ($remoteregservice.Status -eq "Running")
{
    Write-Host -ForegroundColor Green "PASS"
}
else 
{
    Write-Host -ForegroundColor Red "FAIL"
}
Write-Host "Remote registry service startup type is not disabled: " -NoNewline
if ($remoteregservice.StartType -ne "Disabled")
{
    Write-Host -ForegroundColor Green "PASS"
}
else 
{
    Write-Host -ForegroundColor Red "FAIL"
}

Write-Host "`n==> Verifying if the UAC LocalAccountTokenFilterPolicy registry key is set to allow non default administrators to perform scanning.`n"

Write-Host "UAC LocalAccountTokenFilterPolicy registry key set to 1: " -NoNewline

# Gets the specified registry value or $null if it is missing
function Get-RegistryValue($path, $name)
{
    $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if ($key) {
        $key.GetValue($name, $null)
    }
}
$val = Get-RegistryValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system LocalAccountTokenFilterPolicy
if ($val -ne 1) { Write-Host -ForegroundColor Red "FAIL" } else { Write-Host -ForegroundColor Green "PASS" }

Write-Host "`n==> Verifying if the default administrative shares are enabled`n"

# Function to check if a share exists
function Test-Share {
    param([string]$sharePath)
    $share = Get-WmiObject -Class Win32_Share -Filter "Name='$sharePath'"
    return [bool]$share
}

# Check if C$, ADMIN$, and IPC$ shares exist
$isAdminShareEnabled = Test-Share "C$" -and Test-Share "ADMIN$" -and Test-Share "IPC$"

Write-Host "Administrative shares are enabled on this system: " -NoNewline
if ($isAdminShareEnabled) {
    Write-Host -ForegroundColor Green "PASS"
} else {
    Write-Host -ForegroundColor Red "FAIL"
}


$make_changes = Read-Host -Prompt "`nDo you want to make the necessary changes to allow authenticated scanning (Y/N)?"
if ($make_changes -eq "Y")
{
    Write-Host "Disabling firewall and allowing all inbound connections for all profiles..."
    Set-NetFirewallProfile -Name Domain -Enabled False -DefaultInboundAction Allow
    Set-NetFirewallProfile -Name Private -Enabled False -DefaultInboundAction Allow
    Set-NetFirewallProfile -Name Public -Enabled False -DefaultInboundAction Allow

    Write-Host "Enabling and starting the Remote registry service..."
    Set-Service RemoteRegistry -StartupType Manual -Status Running

    Write-Host "Creating the LocalAccountTokenFilterPolicy registry key or setting it to 1 to allow scanning..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Force
}

Write-Host "Performing the authenticated scanning and then press Enter here..."
pause
$revert_changes = Read-Host -Prompt "`nDo you want to revert the changes (Y/N)?"
if ($revert_changes -eq "Y")
{
    Write-Host "Reverting changes after scanning..."
    Write-Host "Enabling firewall and blocking all inbound connections for all profiles..."
    Set-NetFirewallProfile -Name Domain -Enabled True -DefaultInboundAction Block
    Set-NetFirewallProfile -Name Private -Enabled True -DefaultInboundAction Block
    Set-NetFirewallProfile -Name Public -Enabled True -DefaultInboundAction Block
    Write-Host "Disabling and stopping the Remote registry service..."
    Set-Service RemoteRegistry -StartupType Disabled
    Get-Service RemoteRegistry | Stop-Service -Force
    Write-Host "Remove the LocalAccountTokenFilterPolicy registry key or setting it to 0..."
    Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Force
}