# CheckNessusAuthScan

This powershell script performs all pre-checks on a local system to allow Nessus to perform authenticated scanning.

!! Try this on test systems first !!

The scanning requirements are taken from https://docs.tenable.com/nessus/Content/EnableWindowsLoginsForLocalAndRemoteAudits.htm

Starting it with the provided batch file will run it as an administrative user.
Running only the powershell script will run it as currently logged on user.

During the script you can:
+ select which user to use for the authenticated scans
	- currently logged on user
	- another administrator account
	- the real administrator account - if it was disabled, the account will be enabled and a password will be set
+ Make the necessary changes to allow authenticated scanning
+ Reverted to the previous state after you indicate the scan is finished (will always be done when changes have been made)
	- a random 20 char password will be set for the real administrator account if the password had been changed previously

Example of the output:

+ Current used user account: <computername>\<username>
+ Account is administrator: FAIL
+ Firewall Policy is set to Disabled: 
	- Domain:	FAIL
	- Private:	FAIL
	- Public:	FAIL
+ Firewall DefaultInboundAction is set to Allow: 
	- Domain:	FAIL
	- Private:	FAIL
	- Public:	FAIL
+ Network sharing enabled on selected interface: PASS
+ Remote registry service is running: FAIL
+ Remote registry service startup type is not disabled: FAIL
+ UAC LocalAccountTokenFilterPolicy registry key set to 1: FAIL
+ Administrative shares are enabled on this system: PASS
