# CheckNessusAuthScan

This powershell script performs all pre-checks on a local system to allow Nessus to perform authenticated scanning.

The scanning requirements are taken from https://docs.tenable.com/nessus/Content/EnableWindowsLoginsForLocalAndRemoteAudits.htm

Starting it with the provided batch file will run it as an administrative user.

Running only the powershell script will run it as currently logged on user.

Example of the output:

Current used user account: <computername>\<username>
Account is administrator: FAIL
Firewall Policy is set to Disabled: 
+ Domain:	FAIL
+ Private:	FAIL
+ Public:	FAIL
Firewall DefaultInboundAction is set to Allow: 
+ Domain:	FAIL
+ Private:	FAIL
+ Public:	FAIL
Network sharing enabled on selected interface: PASS
Remote registry service is running: FAIL
Remote registry service startup type is not disabled: FAIL
UAC LocalAccountTokenFilterPolicy registry key set to 1: FAIL
Administrative shares are enabled on this system: PASS
