# CheckNessusAuthScan.ps1
#
# Can be used to perform pre-checks to allow Nessus Authenticated scans
# Requirements are from https://docs.tenable.com/nessus/Content/EnableWindowsLoginsForLocalAndRemoteAudits.htm
#
# Created by Dieter Sarrazyn (dieter at secudea dot be or dieter at securiacs dot com)
#
# GPL 3.0 licensed

Write-Host "`n====================================================================================="
Write-Host "`n This script checks for the requirements to allow Nessus Authenticated scans against "
Write-Host " standalone systems and allows you to change the system should some of these "
Write-Host " requirements show up as failed. After scanning you can revert back to the original"
Write-Host " settings prior to the authenticated scanning."
Write-Host "`n====================================================================================="

# Custom function to read Y or y answers from questions and return a boolean value
function Read-Boolean {
    param (
        [string]$Question
    )

    $response = Read-Host -prompt $Question
    $booleanValue = ($response -eq 'Y' -or $response -eq 'y')
    return $booleanValue
}

# Custom function to read input and verify it to be an integer
function Read-Integer {
    param (
        [string]$Question
    )

    $isValidInteger = $false
    $intValue = 0

    while (-not $isValidInteger) {
        $inputValue = Read-Host -prompt $Question
        $isValidInteger = [int]::TryParse($inputValue, [ref]$intValue)

        if (-not $isValidInteger) {
            Write-Host "Invalid input. Please enter a valid integer."
        }
    }

    return $intValue
}

function IsBuiltInAdministrator {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SID
    )

    # Check if the SID ends with -500
    if ($SID -match '-500$') {
        return $true
    } else {
        return $false
    }
}

function Generate-RandomPassword {
    param (
        [int]$length
    )

    # Define the characters allowed in the password
    $characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+{}|:<>?"

    # Generate a random password
    $securePassword = ""
    $random = New-Object System.Random
    for ($i = 0; $i -lt $length; $i++) {
        $randomIndex = $random.Next(0, $characters.Length)
        $securePassword += $characters[$randomIndex]
    }

    return $securePassword
}

# BEGINNING OF SCRIPT

$realadmin = $false
$selectedaccount = ""
$user_choice = Read-Boolean -Question "`nDo you want to use the currently logged on user for the authenticated scans (Y/N)?"
if ($user_choice)
{
    # Getting the current logged on user and verify whether it is a local administrator account or not
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUserName = $currentPrincipal.Identities.Name
    $isadmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $selectedaccount = $currentUserName
    $realadmin = IsBuiltInAdministrator -SID $currentPrincipal.Identity.User.Value
}
else
{
    # Getting list of local administrative users and let the user select one
    $administratorsGroup = Get-LocalGroupMember -Group "Administrators"
    $adminsArray = @()
    $index = 1

    Write-Host "`nList of the local Administrators on this system:`n"

    foreach ($member in $administratorsGroup) {
        $name = $member.Name
        $realadmin = IsBuiltInAdministrator -SID $member.SID
        $adminsArray += [PSCustomObject]@{
            RowNumber = $index
            Name = $name
            ID = $member.SID
            RealAdmin = $realadmin
        }
        Write-Host $index -NoNewline
        Write-Host " - " -NoNewline
        Write-Host $name -NoNewline
        if ($realadmin) 
        {
            Write-Host " (Real Administrator)"
        }
        else 
        {
            Write-Host ""
        }
        $index++
    }

    $selectedAccountId = Read-Integer -Question "`nSelect the administrator account you want to use for authenticated scans"
    $rowNumber = [int]$selectedAccountId
    $selectedAdmin  = $adminsArray | Where-Object { $_.RowNumber -eq $rowNumber }
    $realadmin = $selectedAdmin.RealAdmin
    $selectedaccount =  $selectedAdmin.Name
    $isadmin = $true
}
Write-Host "Selected user account: " -NoNewline
Write-Host $selectedaccount
Write-Host "Account is administrator: " -NoNewline
if ($isadmin) { Write-Host -ForegroundColor Green "PASS" }
else { Write-Host -ForegroundColor Red "FAIL" }

# Getting the Interface and IP address information to identify the interface on the system that will be used for authenticated scanning

$Interfaces = Get-NetIPConfiguration | Select-object InterfaceDescription -ExpandProperty AllIPAddresses | Where-Object { $_.IPAddress -notmatch "^(::1|fe80::|169\.254\.\d{1,3}\.\d{1,3})" } | Select ifIndex, IPAddress, PrefixLength, InterfaceAlias  | Format-Table *

Write-Output $Interfaces
$scanning_interface_id = Read-Integer -Question "Enter the Interface Index that will be used for the authenticated scan"
$scanning_interface = Get-NetIPConfiguration | Where-Object { $_.InterfaceIndex -eq $scanning_interface_id }
$scanning_interface_deviceid = $scanning_interface.NetAdapter.DeviceID

Write-Host -ForegroundColor Yellow "`nVerifying the firewall policies and Default Inbound Actions that are configured on the system."
Write-Host -ForegroundColor Yellow "For each profile, either the Policy or the Default Inbound Action showing up as PASS is ok...`n"

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

Write-Host -ForegroundColor Yellow "`nVerifying if the network sharing service is installed on the selected interface...`n"

$instance_filter = $scanning_interface_deviceid + "::ms_server"
$adapter_bindings = Get-NetAdapterBinding | Where-Object { $_.InstanceID -eq $instance_filter } | Select-Object Name, Enabled
$adapter_binding = $adapter_bindings.Enabled

Write-Host "Network sharing enabled on selected interface ($($adapter_bindings.Name)): " -NoNewline
if ($adapter_binding)
{
    Write-Host -ForegroundColor Green "PASS"
}
else 
{
    Write-Host -ForegroundColor Red "FAIL"
}

Write-Host -ForegroundColor Yellow "`nVerifying if the remote registry service is started and what its startup type is set to...`n"

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

Write-Host -ForegroundColor Yellow "`nVerifying if the UAC LocalAccountTokenFilterPolicy registry key is set to allow non default administrators to perform scanning...`n"

Write-Host "UAC LocalAccountTokenFilterPolicy registry key set to 1: " -NoNewline

# Gets the specified registry value or $null if it is missing
function Get-RegistryValue($path, $name)
{
    $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if ($key) {
        $key.GetValue($name, $null)
    }
}
$LocalAccountTokenFilterPolicy = Get-RegistryValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System LocalAccountTokenFilterPolicy
if ($LocalAccountTokenFilterPolicy -ne 1) { Write-Host -ForegroundColor Red "FAIL" } else { Write-Host -ForegroundColor Green "PASS" }

Write-Host -ForegroundColor Yellow "`nVerifying if the default administrative shares are enabled...`n"

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

# Check if the administrative shares are created automatically - Wks or Server
Write-Host "Administrative shares are automatically started after a reboot: " -NoNewline
$autoShareWksValue = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Name AutoShareWks
$autoShareServerValue = Get-ItemProperty -Path  HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Name AutoShareServer
if (($autoShareWksValue -eq 0) -or ($autoShareServerValue -eq 0))
{
    Write-Host -ForegroundColor Red "FAIL"
}
else
{
    Write-Host -ForegroundColor Green "PASS"
}


$make_changes = Read-Boolean -Question "`nDo you want to make the necessary changes to allow authenticated scanning (Y/N)?"
if ($make_changes)
{
    # in this choice, the previous states are not looked at, all necessary changes are done to make sure auth scanning will be succesfull.

    if ($realadmin) 
    {
        # Check if the account is disabled or not
        $computerName, $accountName = $selectedaccount -split "\\"
        $isEnabled = (Get-LocalUser $accountName -ErrorAction Stop).enabled
        if ($isEnabled)
        {
            Write-Host -ForeGroundColor Yellow "You selected to use the Real Administrator..."
            $continuerealadmin = Read-Boolean -Question "Do you want to continue using the real administrator (Y/N)?"
            $continuerealadminchangepass = Read-Boolean -Question "Do you want to change the password of the real administrator (Y/N)?"
        }
        else
        {
            Write-Host -ForeGroundColor Yellow "You selected to use the Real Administrator while it is disabled..."
            Write-Host -ForeGroundColor Yellow "If you continue, the password will be reset and the account enabled when you are making the changes..."
            $continuerealadminchangepassenable = Read-Boolean -Question "Do you want to continue using the real administrator, enable the account and change the password (Y/N)?"
        }
        if ($continuerealadminchangepass)
        {
            # Prompt for password input securely
            $securePassword = Read-Host -Prompt "Enter the new password for the user account" -AsSecureString
            # Set the password for the user account
            Set-LocalUser -Name $accountName -Password $securePassword
        }
        if ($continuerealadminchangepassenable)
        {
            # Enabling the account and setting the password
            Enable-LocalUser -Name $accountName
            # Prompt for password input securely
            $securePassword = Read-Host -Prompt "Enter the new password for the user account" -AsSecureString
            # Set the password for the user account
            Set-LocalUser -Name $accountName -Password $securePassword
        }
    }

    # Both the firewall state as well as the Default Inbound Actions are changed as sometimes, Group policies prevent disabling the firewall
    Write-Host "Disabling firewall and allowing all inbound connections for all profiles..."
    Set-NetFirewallProfile -Name Domain -Enabled False -DefaultInboundAction Allow
    Set-NetFirewallProfile -Name Private -Enabled False -DefaultInboundAction Allow
    Set-NetFirewallProfile -Name Public -Enabled False -DefaultInboundAction Allow

    # Set the startup type to Manual for the remote registry service and start it
    Write-Host "Enabling and starting the Remote registry service..."
    Set-Service RemoteRegistry -StartupType Manual -Status Running

    # Allowing remote access to the Admin shares even if UAC is enabled
    Write-Host "Creating the LocalAccountTokenFilterPolicy registry key or setting it to 1 to allow scanning..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Force

    # Enable the ms_server adapter binding if it is not enabled
    if (-not($adapter_binding))
    {
        Write-Host "Enabling the Windows network sharing binding on the interface..."
        Enable-NetAdapterBinding -Name $($adapter_bindings.Name) -ComponentID ms_server
    }

    # Setting the automatic creation of admin shares and restart the server service
    if (($autoShareWksValue -eq 0) -or ($autoShareServerValue -eq 0))
    {
        Write-Host "Making sure that the administrative shares are started during boot and restart the LanmanServer service to enable these..."
        if ($autoShareWksValue -eq 0) {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 1 -Force}
        if ($autoShareServerValue -eq 0) {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Value 1 -Force}
        Restart-Service -Name LanmanServer
    }

    Write-Host -ForegroundColor Red "!! Do NOT close this script while scanning or reverting to previous settings will no longer be possible !!"
    Read-Host -prompt "Perform the authenticated scanning and then press Enter to continue the script and restore to the previous state ..."
        Write-Host "Reverting changes after scanning..."
        Write-Host "Re-enabling firewall and setting the Default Inbound Action back to previous settings..."
        # Firewall profile and policy values have been queried before and stored in the fw_policies variable
        Foreach ($fw_policy in $fw_policies)
        {
            Set-NetFirewallProfile -Name $($fw_policy.Name) -Enabled $($fw_policy.Enabled) -DefaultInboundAction $($fw_policy.DefaultInboundAction)
        }

        # Remote registry service previous value is stored in remoteregservice.StartType - we'll stop the service afterwards, regardless if it was previously running
        # if the service is needed and startuptype is set to manual or automatic, it will fire up when needed
        Write-Host "Disabling and stopping the Remote registry service..."
        Set-Service RemoteRegistry -StartupType $($remoteregservice.StartType)
        Get-Service RemoteRegistry | Stop-Service -Force

        # The previous state is stored in LocalAccountTokenFilterPolicy - if this variable is null, the created value is removed.
        # if it was not null, the previous value is restored
        Write-Host "Remove the LocalAccountTokenFilterPolicy registry key or setting it (back) to 0..."
        if ($LocalAccountTokenFilterPolicy -eq $null)
        {
            Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Force
        }
        else
        {
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 0
        }

        # Reset the adapter_binding to what it was before
        Write-Host "Resetting the network adapter binding..."
        if ($adapter_binding)
        {
            Enable-NetAdapterBinding -Name $($adapter_bindings.Name) -ComponentID ms_server
        }
        else 
        {
            Disable-NetAdapterBinding -Name $($adapter_bindings.Name) -ComponentID ms_server
        }

        # Resetting the automatic creation of admin shares and restart the server service
        Write-Host "Resetting the admin shares automatic creation ..."
        if (($autoShareWksValue -eq 0) -or ($autoShareServerValue -eq 0))
        {
            if ($autoShareWksValue -eq 0) {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0 -Force}
            if ($autoShareServerValue -eq 0) {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Value 0 -Force}
        }

        Restart-Service -Name LanmanServer

        # If the admin account has been enabled and password changed, reset the password to random value and disable the account
        if ($continuerealadminchangepassenable)
        {
            Write-Host "Disabling the local Administrator account ..."
            # Disabling the account and setting the password
            Disable-LocalUser -Name $accountName
            # Prompt for password input securely
            $Password = Generate-RandomPassword -length 20
            $securePassword = ConvertTo-SecureString -AsPlainText $Password -Force
            # Set the password for the user account
            Set-LocalUser -Name $accountName -Password $securePassword
            Write-Host "Setting a random password for the local Administrator account ..."
        }
        if ($continuerealadminchangepass)
        {
            # Prompt for password input securely
            $Password = Generate-RandomPassword -length 20
            $securePassword = ConvertTo-SecureString -AsPlainText $Password -Force
            # Set the password for the user account
            Set-LocalUser -Name $accountName -Password $securePassword
            Write-Host "Setting a random password for the local Administrator account ..."
        }

        Write-Host "`nThe system has been restored to its previous state`n"
}

pause
