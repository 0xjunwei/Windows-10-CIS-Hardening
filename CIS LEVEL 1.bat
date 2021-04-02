::Search for "Requires customization" within this batch file to modify the values to suit organization needs


:: 2.3.1.2 Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoConnectedUser" /t REG_DWORD /d 3 /f

:: 2.3.2.1 Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "SCENoApplyLegacyAuditPolicy" /t REG_DWORD /d 1 /f

::2.3.4.1 Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators and Interactive Users'
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AllocateDASD" /t REG_SZ /d 2 /f

::2.3.7.1 Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCAD" /t REG_DWORD /d 0 /f

::2.3.7.2 Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DontDisplayLastUserName" /t REG_DWORD /d 1 /f

::2.3.7.4 Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "InactivityTimeoutSecs" /t REG_DWORD /d 900 /f

::2.3.7.9 Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher'
::Requires customization
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "SCRemoveOption" /t REG_SZ /d 1 /f

::2.3.8.1 Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f

::2.3.9.2 Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f

::2.3.9.3 Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f

::2.3.9.5 Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" /v "SMBServerNameHardeningLevel" /t REG_DWORD /d 1 /f

::2.3.10.3 Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f

::2.3.10.4 Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" /t REG_DWORD /d 1 /f

::2.3.10.10 Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "restrictremotesam" /t REG_SZ /d 1 /f

::2.3.11.1 Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "UseMachineId" /t REG_DWORD /d 1 /f

::2.3.11.2 Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
reg add "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /v "AllowNullSessionFallback" /t REG_DWORD /d 0 /f

::2.3.11.3 Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
reg add "HKLM\System\CurrentControlSet\Control\Lsa\pku2u" /v "AllowOnlineID" /t REG_DWORD /d 0 /f

::2.3.11.4 Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v "SupportedEncryptionTypes" /t REG_DWORD /d 2147483640 /f

::2.3.11.7 Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "LmCompatibilityLevel" /t REG_DWORD /d 5 /f

::2.3.11.9 Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
reg add "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /v "NTLMMinClientSec" /t REG_DWORD /d 537395200 /f

::2.3.11.10 Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
reg add "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /v "NTLMMinServerSec" /t REG_DWORD /d 537395200 /f

::2.3.17.1 Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d 1 /f

::2.3.17.2 Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 2 /f

::2.3.17.3 Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d 0 /f

::2.3.17.6 Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f

::5.7 Ensure 'Infrared monitor service (irmon)' is set to 'Disabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\irmon" /v "Start" /t REG_DWORD /d 4 /f

::5.8 Ensure 'Internet Connection Sharing (ICS) (SharedAccess)' is set to 'Disabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess" /v "Start" /t REG_DWORD /d 4 /f

::5.24 Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator" /v "Start" /t REG_DWORD /d 4 /f

::5.30 Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" /v "Start" /t REG_DWORD /d 4 /f

::5.31 Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\upnphost" /v "Start" /t REG_DWORD /d 4 /f

::5.35 Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is set to 'Disabled' or 'Not Installed'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d 4 /f

::5.36 Ensure 'Windows Mobile Hotspot Service (icssvc)' is set to 'Disabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" /v "Start" /t REG_DWORD /d 4 /f

::5.41 Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d 4 /f

::5.42 Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d 4 /f

::5.43 Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d 4 /f

::5.44 Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' is set to 'Disabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d 4 /f

::9.1.1 Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"/v "EnableFirewall" /t REG_DWORD /d 1 /f

::9.1.2 Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultInboundAction" /t REG_DWORD /d 1 /f

::9.1.3 Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultOutboundAction" /t REG_DWORD /d 0 /f

::9.1.4 Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d 1 /f

::9.1.5 Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogFilePath" /t REG_SZ /d "%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log" /f

::9.1.6 Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'
::Requires customization
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogFileSize" /t REG_DWORD /d 16384 /f

::9.1.7 Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d 1 /f

::9.1.8 Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogSuccessfulConnections" /t REG_DWORD /d 1 /f

::9.2.1 Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f

::9.2.2 Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultInboundAction" /t REG_DWORD /d 1 /f

::9.2.3 Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultOutboundAction" /t REG_DWORD /d 0 /f

::9.2.4 Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DisableNotifications" /t REG_DWORD /d 1 /f

::9.2.5 Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogFilePath" /t REG_SZ /d "%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log" /f

::9.2.6 Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'
::Requires customization
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogFileSize" /t REG_DWORD /d 16384 /f

::9.2.7 Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d 1 /f

::9.2.8 Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogSuccessfulConnections" /t REG_DWORD /d 1 /f

::9.3.1 Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f

::9.3.2 Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DefaultInboundAction" /t REG_DWORD /d 1 /f

::9.3.3 Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DefaultOutboundAction" /t REG_DWORD /d 0 /f

::9.3.4 Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d 1 /f

::9.3.5 Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d 0 /f

::9.3.6 Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d 0 /f

::9.3.7 Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogFilePath" /t REG_SZ /d "%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log" /f

::9.3.8 Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'
::Requires customization
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogFileSize" /t REG_DWORD /d 16384 /f

::9.3.9 Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d 1 /f

::9.3.10 Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogSuccessfulConnections" /t REG_DWORD /d 1 /f

::18.1.1.1 Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f

::18.1.1.2 Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenSlideshow" /t REG_DWORD /d 1 /f

::18.1.2.2 Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f



::18.2.2 Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'
::Requires customization (if LAPS is not install comment out the reg by adding ::)
reg add "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" /v "PwdExpirationProtectionEnabled" /t REG_DWORD /d 1 /f

::18.2.3 Ensure 'Enable Local Admin Password Management' is set to 'Enabled'
::Requires customization (if LAPS is not install comment out the reg by adding ::)
reg add "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" /v "AdmPwdEnabled" /t REG_DWORD /d 1 /f

::18.2.4 Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'
::Requires customization (if LAPS is not install comment out the reg by adding ::)
reg add "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" /v "PasswordComplexity" /t REG_DWORD /d 4 /f

::18.2.5 Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'
::Requires customization (if LAPS is not install comment out the reg by adding ::)
reg add "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" /v "PasswordLength" /t REG_DWORD /d 15 /f

::18.2.6 Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'
::Requires customization (if LAPS is not install comment out the reg by adding ::)
reg add "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" /v "PasswordAgeDays" /t REG_DWORD /d 30 /f



::18.3.1 Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 0 /f

::18.3.2 Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v "Start" /t REG_DWORD /d 4 /f

::18.3.3 Ensure 'Configure SMB v1 server' is set to 'Disabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f

::18.3.4 Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'
::Requires customization (After SEHOP enabled cygwin, Skype, and Armadillo-protected Applications may not work correctly
::Uncomment the command below if you wish SEHOP to be enabled
::reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d 0 /f

::18.3.5 Ensure 'WDigest Authentication' is set to 'Disabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d 0 /f

::18.4.2 Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d 2 /f

::18.4.3 Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d 2 /f

::18.4.5 Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d 0 /f

::18.4.7 Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "nonamereleaseondemand" /t REG_DWORD /d 1 /f

::18.4.9 Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "SafeDllSearchMode" /t REG_DWORD /d 1 /f

::18.4.10 Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
::Requires Customization (choose the seconds between 1-5)
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "ScreenSaverGracePeriod" /t REG_DWORD /d 5 /f

::18.4.13 Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
::Requires Customization (Choose the percentage according to company risk appetite)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" /v "WarningLevel" /t REG_DWORD /d 90 /f

::18.5.4.1 Set 'NetBIOS node type' to 'P-node' (Ensure NetBT Parameter 'NodeType' is set to '0x2 (2)')
reg add "HKLM\System\CurrentControlSet\Services\Netbt\Parameters" /v "NodeType" /t REG_DWORD /d 2 /f

::18.5.4.2 Ensure 'Turn off multicast name resolution' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d 0 /f

::18.5.8.1 Ensure 'Enable insecure guest logons' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v "AllowInsecureGuestAuth" /t REG_DWORD /d 0 /f

::18.5.11.2 Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_AllowNetBridge_NLA" /t REG_DWORD /d 0 /f

::18.5.11.3 Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_ShowSharedAccessUI" /t REG_DWORD /d 0 /f

::18.5.11.4 Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\Network Connections" /v "NC_StdDomainUserSetLocation" /t REG_DWORD /d 1 /f

::18.5.14.1 Ensure 'Hardened UNC Paths' is set to 'Enabled, with 'Require Mutual Authentication' and 'Require Integrity' set for all NETLOGON and SYSVOL shares' - NETLOGON
::Require Customization (Only applicable to domain joined computers, standalone are NA)
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v "\\*\NETLOGON" /t REG_SZ /d "RequireMutualAuthentication=1, RequireIntegrity=1" /f

::18.5.14.1 Ensure 'Hardened UNC Paths' is set to 'Enabled, with 'Require Mutual Authentication' and 'Require Integrity' set for all NETLOGON and SYSVOL shares' - SYSVOL
::Require Customization (Only applicable to domain joined computers, standalone are NA)
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v "\\*\SYSVOL" /t REG_SZ /d "RequireMutualAuthentication=1, RequireIntegrity=1" /f

::18.5.21.1 Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
::Require Customization (custom set 1-3 ranmge)
reg add "HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fMinimizeConnections" /t REG_DWORD /d 3 /f

::18.5.21.2 Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fBlockNonDomain" /t REG_DWORD /d 1 /f

::18.5.23.2.1 Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f

::18.8.3.1 Ensure 'Include command line in process creation events' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d 0 /f

::18.8.4.1 Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v "AllowEncryptionOracle" /t REG_DWORD /d 0 /f

::18.8.4.2 Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowProtectedCreds" /t REG_DWORD /d 1 /f

::18.8.14.1 Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
reg add "HKLM\System\CurrentControlSet\Policies\EarlyLaunch" /v "DriverLoadPolicy" /t REG_DWORD /d 3 /f

::18.8.21.2 Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
reg add "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v "NoBackgroundPolicy" /t REG_DWORD /d 0 /f

::18.8.21.3 Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
reg add "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v "NoGPOListChanges" /t REG_DWORD /d 0  /f

::18.8.21.4 Ensure 'Continue experiences on this device' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableCdp" /t REG_DWORD /d 0 /f

::18.8.22.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v "DisableWebPnPDownload" /t REG_DWORD /d 1 /f

::18.8.22.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d 1 /f

::18.8.28.1 Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "BlockUserFromShowingAccountDetailsOnSignin" /t REG_DWORD /d 1 /f

::18.8.28.2 Ensure 'Do not display network selection UI' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DontDisplayNetworkSelectionUI" /t REG_DWORD /d 1 /f

::18.8.28.3 Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DontEnumerateConnectedUsers" /t REG_DWORD /d 1 /f

::18.8.28.4 Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnumerateLocalUsers" /t REG_DWORD /d 0 /f

::18.8.28.5 Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableLockScreenAppNotifications" /t REG_DWORD /d 1 /f 

::18.8.28.6 Ensure 'Turn off picture password sign-in' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "BlockDomainPicturePassword" /t REG_DWORD /d 1 /f

::18.8.28.7 Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowDomainPINLogon" /t REG_DWORD /d 0 /f

::18.8.34.6.1 Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'
::Require Customization (Please refer to specific OS Flavour to adjust the value after PowerSettings
reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" /v "DCSettingIndex" /t REG_DWORD /d 0 /f

::18.8.34.6.2 Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'
::Require Customization (Please refer to specific OS Flavour to adjust the value after PowerSettings
reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" /v "ACSettingIndex" /t REG_DWORD /d 0 /f

::18.8.34.6.5 Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'
::Require Customization (Please refer to specific OS Flavour to adjust the value after PowerSettings
reg add "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "DCSettingIndex" /t REG_DWORD /d 1 /f

::18.8.34.6.6 Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'
::Require Customization (Please refer to specific OS Flavour to adjust the value after PowerSettings
reg add "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "ACSettingIndex" /t REG_DWORD /d 1 /f

::18.8.36.1 Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
reg add "HKLM\Software\policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f

::18.8.36.2 Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
reg add "HKLM\Software\policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f

::18.8.37.1 Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Rpc" /v "EnableAuthEpResolution" /t REG_DWORD /d 1 /f

::18.8.37.2 Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Rpc" /v "RestrictRemoteClients" /t REG_DWORD /d 1 /f

::18.9.6.1 Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "MSAOptional" /t REG_DWORD /d 1 /f

::18.9.8.1 Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f

::18.9.8.2 Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f

::18.9.8.3 Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

::18.9.10.1.1 Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v "EnhancedAntiSpoofing" /t REG_DWORD /d 1 /f

::18.9.13.1 Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f


::18.9.14.1 Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'
::Requires Customization (1 or 2 based on first time or always)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect" /v "RequirePinForPairing" /t REG_DWORD /d 2 /f

::18.9.15.1 Ensure 'Do not display the password reveal button' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d 1 /f

::18.9.15.2 Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" /v "EnumerateAdministrators" /t REG_DWORD /d 0 /f

::18.9.16.1 Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'
::Requires Customization (choose between 1 or 0)
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 1 /f

::18.9.16.3 Ensure 'Do not show feedback notifications' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f

::18.9.16.4 Ensure 'Toggle user control over Insider builds' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f

::18.9.17.1 Ensure 'Download Mode' is NOT set to 'Enabled: Internet (3)'
::Requires Customization (From CIS Guide choose the mode)
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 1 /f

::18.9.26.1.1 Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\Application" /v "Retention" /t REG_SZ /d 0 /f

::18.9.26.1.2 Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\Application" /v "MaxSize" /t REG_DWORD /d 32768 /f 

::18.9.26.2.1 Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" /v "Retention" /t REG_SZ /d 0 /f

::18.9.26.2.2 Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" /v "MaxSize" /t REG_DWORD /d 196608 /f

::18.9.26.3.1 Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup" /v "Retention" /t REG_SZ /d 0 /f

::18.9.26.3.2 Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup" /v "MaxSize" /t REG_DWORD /d 32768 /f

::18.9.26.4.1 Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\System" /v "Retention" /t REG_SZ /d 0 /f

::18.9.26.4.2 Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\System" /v "MaxSize" /t REG_DWORD /d 32768 /f

::18.9.30.2 Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f

::18.9.30.3 Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoHeapTerminationOnCorruption" /t REG_DWORD /d 0 /f

::18.9.30.4 Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "PreXPSP2ShellProtocolBehavior" /t REG_DWORD /d 0 /f

::18.9.35.1 Ensure 'Prevent the computer from joining a homegroup' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\HomeGroup" /v "DisableHomeGroup" /t REG_DWORD /d 1 /f

::18.9.44.1 Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount" /v "DisableUserAuth" /t REG_DWORD /d 1 /f

::18.9.45.4 Ensure 'Allow Sideloading of extension' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Extensions" /v "AllowSideloadingOfExtensions" /t REG_DWORD /d 0 /f

::18.9.45.5 Ensure 'Configure cookies' is set to 'Enabled: Block only 3rd-party cookies' or higher
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "Cookies" /t REG_DWORD /d 1 /f 

::18.9.45.6 Ensure 'Configure Password Manager' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d "no" /f

::18.9.45.9 Ensure 'Configure the Adobe Flash Click-to-Run setting' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Security" /v "FlashClickToRunMode" /t REG_DWORD /d 1 /f

::18.9.45.11 Ensure 'Prevent certificate error overrides' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings" /v "PreventCertErrorOverrides" /t REG_DWORD /d 1 /f

::18.9.52.1 Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f

::18.9.59.2.2 Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f

::18.9.59.3.3.2 Ensure 'Do not allow drive redirection' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDisableCdm" /t REG_DWORD /d 1 /f

::18.9.59.3.9.1 Ensure 'Always prompt for password upon connection' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fPromptForPassword" /t REG_DWORD /d 1 /f

::18.9.59.3.9.2 Ensure 'Require secure RPC communication' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fEncryptRPCTraffic" /t REG_DWORD /d 1 /f

::18.9.59.3.9.3 Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "SecurityLayer" /t REG_DWORD /d 2 /f

::18.9.59.3.9.4 Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "UserAuthentication" /t REG_DWORD /d 1 /f

::18.9.59.3.9.5 Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "MinEncryptionLevel" /t REG_DWORD /d 3 /f

::18.9.59.3.11.1 Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DeleteTempDirsOnExit" /t REG_DWORD /d 1 /f

::18.9.59.3.11.2 Ensure 'Do not use temporary folders per session' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "PerSessionTempDir" /t REG_DWORD /d 1 /f

::18.9.60.1 Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v "DisableEnclosureDownload" /t REG_DWORD /d 1 /f

::18.9.61.3 Ensure 'Allow Cortana' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f

::18.9.61.4 Ensure 'Allow Cortana above lock screen' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f

::18.9.61.5 Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d 0 /f

::18.9.61.6 Ensure 'Allow search and Cortana to use location' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f

::18.9.69.2 Ensure 'Only display the private store within the Microsoft Store' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "RequirePrivateStoreOnly" /t REG_DWORD /d 1 /f

::18.9.69.3 Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d 4 /f

::18.9.69.4 Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "DisableOSUpgrade" /t REG_DWORD /d 1 /f

::18.9.77.3.1 Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'
::This is only able to be performed via GP however this is the registry key checked
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0 /f

::18.9.77.7.1 Ensure 'Turn on behavior monitoring' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 0 /f

::18.9.77.10.1 Ensure 'Scan removable drives' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableRemovableDriveScanning" /t REG_DWORD /d 0 /f

::18.9.77.10.2 Ensure 'Turn on e-mail scanning' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /t REG_DWORD /d 0 /f

::18.9.77.13.1.1 Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" /v "ExploitGuard_ASR_Rules" /t REG_DWORD /d 1 /f

::18.9.77.13.1.2 Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured' - 26190899-1602-49e8-8b27-eb1d0a1ce869
::Requires Customization(Depending on organization rules, disable what is not needed)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "26190899-1602-49e8-8b27-eb1d0a1ce869" /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "3b576869-a4ec-4529-8536-b80a7769e899" /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "5beb7efe-fd9a-4556-801d-275e5ffc04cc" /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "d3e037e1-3eb8-44c8-a917-57927947596d" /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "d4f940ab-401b-4efc-aadc-ad5f3c50688a" /t REG_SZ /d 1 /f

::18.9.77.13.3.1 Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v "EnableNetworkProtection" /t REG_DWORD /d 1 /f

::18.9.77.14 Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d 1 /f

::18.9.77.15 Ensure 'Turn off Windows Defender AntiVirus' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f

::18.9.80.1.1 Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' - EnableSmartScreen
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 1 /f

::18.9.80.1.1 Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' - ShellSmartScreenLevel
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "Block" /f

::18.9.80.2.1 Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f

::18.9.80.2.2 Ensure 'Prevent bypassing Windows Defender SmartScreen prompts for files' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "PreventOverrideAppRepUnknown" /t REG_DWORD /d 1 /f

::18.9.80.2.3 Ensure 'Prevent bypassing Windows Defender SmartScreen prompts for sites' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d 1 /f

::18.9.82.1 Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f

::18.9.84.2 Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'
::Requires Customization (Please select)
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d 1 /f

::18.9.85.1 Ensure 'Allow user control over installs' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\Installer" /v "EnableUserControl" /t REG_DWORD /d 0 /f

::18.9.85.2 Ensure 'Always install with elevated privileges' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d 0 /f

::18.9.86.1 Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d 1 /f

::18.9.95.1 Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d 0 /f

::18.9.95.2 Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v "EnableTranscripting" /t REG_DWORD /d 0 /f

::18.9.97.1.1 Ensure 'Allow Basic authentication' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" /v "AllowBasic" /t REG_DWORD /d 0 /f

::18.9.97.1.2 Ensure 'Allow unencrypted traffic' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" /v "AllowUnencryptedTraffic" /t REG_DWORD /d 0 /f

::18.9.97.1.3 Ensure 'Disallow Digest authentication' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" /v "AllowDigest" /t REG_DWORD /d 0 /f

::18.9.97.2.1 Ensure 'Allow Basic authentication' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" /v "AllowBasic" /t REG_DWORD /d 0 /f

::18.9.97.2.4 Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" /v "DisableRunAs" /t REG_DWORD /d 1 /f

::18.9.99.2.1 Ensure 'Prevent users from modifying settings' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v "DisallowExploitProtectionOverride" /t REG_DWORD /d 1 /f

::18.9.102.1.1 Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds'
::Requires Customization (Either 1 or 0) refer to CIS
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuilds" /t REG_DWORD /d 1 /f

::18.9.102.1.2 Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days' - DeferFeatureUpdates
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdates" /t REG_DWORD /d 1 /f

::18.9.102.1.2 Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days' - DeferFeatureUpdatesPeriodInDays
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d 180 /f

::18.9.102.1.2 Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days' - BranchReadinessLevel
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "BranchReadinessLevel" /t REG_DWORD /d 32 /f

::18.9.102.1.3 Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days' - DeferQualityUpdates
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferQualityUpdates" /t REG_DWORD /d 1 /f

::18.9.102.1.3 Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days' - DeferQualityUpdatesPeriodInDays
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferQualityUpdatesPeriodInDays" /t REG_DWORD /d 0 /f

::18.9.102.2 Ensure 'Configure Automatic Updates' is set to 'Enabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 0 /f

::18.9.102.3 Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallDay" /t REG_DWORD /d 0 /f

::18.9.102.4 Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d 0 /f

::18.9.102.5 Ensure 'Remove access to Pause updates feature' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisablePauseUXAccess" /t REG_DWORD /d 1 /f

::19.1.3.1 Ensure 'Enable screen saver' is set to 'Enabled'
reg add "HKU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d 1 /f

::19.1.3.2 Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'
reg add "HKU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d "scrnsave.scr" /f

::19.1.3.3 Ensure 'Password protect the screen saver' is set to 'Enabled'
reg add "HKU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d 1 /f

::19.1.3.4 Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'
::Requires Customization (choose timeout)
reg add "HKU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_SZ /d 900 /f

::19.5.1.1 Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'
reg add "HKU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d 1 /f

::19.7.4.1 Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'
reg add "HKU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 2 /f

::19.7.4.2 Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'
reg add "HKU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f

::19.7.7.1 Ensure 'Configure Windows spotlight on lock screen' is set to Disabled'
reg add "HKU\Software\Policies\Microsoft\Windows\CloudContent" /v "ConfigureWindowsSpotlight" /t REG_DWORD /d 2 /f

::19.7.7.2 Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'
reg add "HKU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d 1 /f

::19.7.26.1 Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'
reg add "HKU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInplaceSharing" /t REG_DWORD /d 1 /f

::19.7.41.1 Ensure 'Always install with elevated privileges' is set to 'Disabled'
reg add "HKU\Software\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d 0 /f
















