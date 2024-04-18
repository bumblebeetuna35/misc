<#
============================================================
	Configuration Manager Client 5.00.9096.1000
============================================================
Date: 	06/04/2020
Author:	Matt Coons
============================================================
Script Details: Powershell.exe -File "_Install-SCCM_Client.ps1" [-Uninstall] [-NoConsoleOutput] [-RemotePC <hostname>]

	Installs Configuration Manager Client 5.00.9096.1000
		*Uninstalls all previous versions prior to installation

Parameters:
	-Uninstall						= Perform an uninstall; Default: $False (switch)
	-ConfigurationItem				= Specify that the action is for an MECM Configuration Item; Default: $False (switch)
	-NoConsoleOutput				= Hide all script output; Default: $False (switch)
	-RemotePC <hostname>			= Execute the installation on the specified remote PC

Template Change Log:
	2020-06-01 Matt Coons
		Version 4.0
		Original Version of template		

Script Change Log:
	2024-01-31 Matt Coons
		Added MOFCOMP prerequisite

	2023-03-10 Matt Coons
		Added remote installation functionality

	2023-03-07 Matt Coons
		Prepared for Client 5.00.9096.1000 (5.00.9096.1000)

	2023-02-28 Matt Coons
		Prepared for Client 5.00.9058.1047 (5.00.9058.1000)
	
	2022-01-26 Matt Coons
		Prepared for Client 5.00.9049.1043 (5.00.9049.1000)

	2021-08-10 Matt Coons
		Prepared for Client 5.00.9040.1044 (5.00.9040.1000)
		Renamed directories to use client version vs product version

	2021-02-25 Matt Coons
		Updated for Client 5.00.9040.1015 (5.00.9040.1000)

#>

#Requires -Version 3.0

Param (
	[switch]$Uninstall,
	[switch]$ConfigurationItem,
	[switch]$NoConsoleOutput,
	[string]$Configuration,
	[switch]$RemoveBeforeInstall = $True,
	[switch]$AllowUpgrade,
	[switch]$RemoveDesktopShortcut,
	[switch]$RemoveStartMenuShortcut,
	[switch]$RemovePinnedShortcut,
	[string]$RemotePC
)

#region----------------[ Declarations ]----------------------------------------------------------

<# ------------------- Product Details ------------------
   ProgramType:
    Auto (Default)	= x64 Application on x64 Workstation: 64-bit registry keys and directories
					  x86 Application on x86 Workstation: 32-bit registry keys and directories
					  
	x86				= x86 Application on x86 OR x64 Workstation: 32-bit registry keys and directories
	
	x64				= x64 Application on x64 Workstation Only: 64-bit registry keys and directories
	
	x86_x64			= Both x86/x64 Applications on x64 Workstation: 64-bit registry keys and directories
					  x86 Application on x86 Workstation: 32-bit registry keys and directories
-------------------------------------------------------#>
$ProgramType = 'Auto'
$DisplayName = 'Configuration Manager Client'
$DisplayVersion = '5.00.9096.1000'

$ProductCode = '{8FB06CAC-4EC7-45C3-B3F7-A9A09A1515FD}'
$UpgradeCode = '{252DA259-82CA-4177-B8D0-49C78937BA3E}'

$UninstallDisplayName = $DisplayName
#$ExcludeDisplayNames = @('Exclude1','Exclude2')
#$ExcludeDisplayVersions = @('Exclude1','Exclude2')

$ClientVersion = '5.00.9096.1000'
$Source = "\\vm0pwsccasa0001.corp.chartercom.com\EUC\SCCMClient\Client\$ClientVersion"


<# --------------------- Installers ---------------------
   Installer_x86 = Installer for x86 Workstations
   Installer_x64 = Installer for x64 Workstations
-------------------------------------------------------#>
$Installer_x86 = 'ccmsetup.exe'
$Installer_x64 = $Installer_x86


<# ------------------- MSI Transforms -------------------
   Transform_x86 = Transform for x86 Workstations
   Transform_x64 = Transform for x64 Workstations
-------------------------------------------------------#>
$Transform_x86 = ''
$Transform_x64 = $Transform_x86


<# ----------------- Installshield ISS ------------------
   IssFile_x86 = ISS for x86 Workstations
   IssFile_x64 = ISS for x64 Workstations
-------------------------------------------------------#>
$IssFile_x86 = ''
$IssFile_x64 = $IssFile_x86
$IssUninstall = ''


<# --- Abort if Detected Conflicting In-Use Processes ---
   Wildcards permitted
   Abort Conditions: Install/Uninstall/Both/Never
-------------------------------------------------------#>
$AbortProcesses = @('Process1*','Process2*')
$AbortWhen = 'Never'


<# ------- Terminate Conflicting In-Use Processes -------
   Wildcards permitted
   Terminate Conditions: Install/Uninstall/Both/Never
-------------------------------------------------------#>
$TerminateProcesses = @('Process1*','Process2*')
$TerminateWhen = 'Never'


<# ------------------- Custom Logging -------------------
   Wildcards permitted in $LogFromTemp and $UninstLogFromTemp
   Copy Conditions: Install/Uninstall/Both/Never
-------------------------------------------------------#>
$LogFromTemp = @('ccmsetup.log')
$UninstLogFromTemp = @('Logfile1*','Logfile2*')
$TempLogFolder = "$($Env:SystemRoot)\ccmsetup\Logs"
$CopyWhen = 'Install'


<# ----------------- Shortcut Removal ----------------
   Wildcards permitted in each
-------------------------------------------------------#>
If ($RemoveDesktopShortcut) {
	$DesktopShortcut = @('Shortcut1*','Shortcut2*')
}
If ($RemoveStartMenuShortcut) {
	$StartMenuShortcut = @('Shortcut1*','Shortcut2*')
}
If ($RemovePinnedShortcut) {
	$PinnedShortcut = @('Shortcut1*','Shortcut2*')
}


<# -------------- Success/Failure Codes -------------- #>
$SuccessCodes = @(
	0,
	1605,
	1641,
	3010
)
$FailureCodes = @(
	1603,
	1618,
	1619
)


<# ---------------- Error Descriptions --------------- #>
$ErrorDescription = @{
	0 = 'Operation completed successfully';
	1 = 'Invalid ProgramType: Auto, x86_x64, x64 OR x86';
	2 = 'x86 and x64 installers cannot be the same';
	3 = 'x86 installer not specified';
	4 = 'x64 installer not specified';
	5 = 'Application in use';
	6 = 'Installer ERROR or Unable to install x64 version on x86 OS';
	7 = 'Unable to install x86 version on x64 OS';
	8 = 'Setup already running';
	9 = 'Prerequisite evaluation failure';
	10 = 'Setup manifest hash validation failure';
	11 = 'Unable to download installation package from share.  Please ensure you have an active LAN/VPN connection.';
	12 = 'Unable to reach remote PC.  Please ensure you have an active LAN/VPN connection, and the PC is online';
	49 = 'Windows version not supported';
	50 = 'Uninstall skipped, upgrading product';
	99 = 'Installer version is less than the required version';
	998 = 'Please copy this script to the local hard drive to execute.';
	999 = 'This script must be run as an Administrator!';
	1603 = 'Fatal error during installation';
	1605 = 'This action is only valid for products that are currently installed';
	1618 = 'Another installation is already in progress';
	1619 = 'This installation package could not be opened';
	1641 = 'Operation completed successfully, reboot being initiated';
	3010 = 'Operation completed successfully, reboot required'
}


#endregion----------------[ Declarations ]-------------------------------------------------------

#region----------------[ Install Template ]------------------------------------------------------

If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	If (($PSScriptRoot -eq "\\vm0pwsccasa0001.corp.chartercom.com\EUC\SCCMClient") -or ($PSScriptRoot -eq "\\vm0pwsccasa0001\EUC\SCCMClient")) {
		# Must be executed locally
		Write-Host $ErrorDescription.998
		& ECHO $ErrorDescription.998 | MSG * /TIME:300
		[System.Environment]::Exit(998)
	}
	
	If ($RemotePC) {
		If (!(Test-Path "\\$RemotePC\C`$")) {
			Write-Host "$RemotePC UNREACHABLE!"
			& ECHO $ErrorDescription.12 | MSG * /TIME:300
			[System.Environment]::Exit(12)
		}
		If (!(Test-Path "\\$RemotePC\c`$\ProgramData\Support\SCCMClient")) {
			New-Item "\\$RemotePC\c`$\ProgramData\Support\SCCMClient" -ItemType Directory | Out-Null
		}
		Copy-Item -Path "$Source\*" -Destination "\\$RemotePC\c`$\ProgramData\Support\SCCMClient\" -Force
		#Write-Host "waiting...."
		#Start-Sleep -s 30
		$r = Invoke-Command -ComputerName $RemotePC {
			&"C:\ProgramData\Support\SCCMClient\$($Using:MyInvocation.MyCommand.Name)"
		}
	}
	If (!(Test-Path "$PSScriptRoot\Install_Functions.ps1")) {
		Copy-Item -Path "$Source\Install_Functions.ps1" -Destination $PSScriptRoot -Force
	}
	If (Test-Path "$PSScriptRoot\Install_Functions.ps1") {
		. "$PSScriptRoot\Install_Functions.ps1"
	} Else {
		Write-Host 'Install_Functions.ps1 NOT FOUND!'
		& ECHO $ErrorDescription.11 | MSG * /TIME:300
		[System.Environment]::Exit(11)
	}
} Else {
	# Administrator Required
	Write-Host $ErrorDescription.999
	& ECHO $ErrorDescription.999 | MSG * /TIME:300
	[System.Environment]::Exit(999)
}

#endregion----------------[ Install Template ]---------------------------------------------------

#region----------------[ Script Functions ]------------------------------------------------------


#endregion----------------[ Script Functions ]---------------------------------------------------

#region----------------[ Setup Script Log ]------------------------------------------------------

Write-Log '-------------------------------------------------------------------------------------------------------------' -Filename "$DisplayName-$DisplayVersion-$Action-Script.log" -NoTimestamp
Write-Log "Creating $Action Script Log for $DisplayName $DisplayVersion"
Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)"
Write-Log "PSScriptRoot: $PSScriptRoot"
Write-Log "Remote PC: $RemotePC"
Write-Log "ProgramType: $ProgramType"
Write-Log "DisplayName: $DisplayName"
Write-Log "DisplayVersion: $DisplayVersion"
Write-Log "ProductCode: $ProductCode"
Write-Log "UpgradeCode: $UpgradeCode"
Write-Log "Configuration: $Configuration"
Write-Log "ComputerName: $($Env:COMPUTERNAME)"
Write-Log "BitType: $BitType"
Write-Log "SoftwareKey: $SoftwareKey"
Write-Log "ProgramFolder: $ProgramFolder"
Write-Log "CommonFolder: $CommonFolder"
Write-Log "SystemFolder: $SystemFolder"
Write-Log "ProfileFolder: $ProfileFolder"
Write-Log "DesktopFolder: $DesktopFolder"
Write-Log "StartMenuFolder: $StartMenuFolder"
Write-Log "AppDataFolder: $AppDataFolder"
Write-Log "UserStartMenuFolder: $UserStartMenuFolder"
Write-Log "Users: $($Users.Name -Join ',')"
Write-Log "LogFolder: $LogFolder"
Write-Log "CacheFolder: $CacheFolder"

#endregion----------------[ Setup Script Log ]---------------------------------------------------

#region----------------[ Script ]----------------------------------------------------------------

#region Prerequisites
Write-Log $StartTag -FunctionName 'Prerequisites'

<# -- Validate Program Type and Installers -- #>
If ($ProgramType -notIn 'x86','x64') {Abort-Script $ErrorDescription.1 -ExitCode 1}
If ($Installx64Andx86 -and ($Installer_x86 -eq $Installer_x64)) {Abort-Script $ErrorDescription.2 -ExitCode 2}
If ((($ProgramType -eq 'x86') -and ($BitType -eq 'x86') -and !$Installer_x86) -or ($Installx64Andx86 -and !$Installer_x86)) {Abort-Script $ErrorDescription.3 -ExitCode 3}
If ((($ProgramType -in 'x86','x64') -and ($BitType -eq 'x64') -and !$Installer_x64) -or ($Installx64Andx86 -and !$Installer_x64)) {Abort-Script $ErrorDescription.4 -ExitCode 4}

<# -- Check For Conflicting Processes -- #>
If (!$RemotePC -and ((($AbortWhen -in 'Uninstall','Both') -and $Uninstall) -or (($AbortWhen -in 'Install','Both') -and !$Uninstall))) {
	If (Is-Running -Processes $AbortProcesses) {
		$r = 5
		Abort-Script $ErrorDescription.$r -ExitCode $r -UserMessage "$($ErrorDescription.$r). Please close the application and try again."
	}
}

<# -- Download Installation Files / Version Check -- #>
If (!$Uninstall -and !$RemotePC) {
	If (Test-Path "$PSScriptRoot\$Installer") {
		$WorkingDirectory = $PSScriptRoot
		Write-Log 'Skip Download' -FunctionName 'Prerequisites'
	} ElseIf (Test-Path "$Source\$Installer") {
		$WorkingDirectory = "$($Env:ProgramData)\Support\SCCMClient"
		If (!(Test-Path $WorkingDirectory)) {
			Write-Log "New Folder: $WorkingDirectory" -FunctionName 'Prerequisites'
			New-Item -Path $WorkingDirectory -ItemType Directory -Force | Out-Null
		} Else {
			Write-Log "Cleanup Folder: $WorkingDirectory" -FunctionName 'Prerequisites'
			Remove-Item -Path "$WorkingDirectory\*" -Force -Recurse
		}
		Write-Log "Copy: $Source\*" -FunctionName 'Prerequisites'
		Write-Log 'Downloading installation files...' -FunctionName 'Prerequisites'
		Copy-Item -Path "$Source\*" -Destination "$WorkingDirectory\" -Force -Recurse
		Write-Log 'Download completed...' -FunctionName 'Prerequisites'
	} Else {
		# Failed to Download
		$r = 11
		Abort-Script $ErrorDescription.$r -ExitCode $r -UserMessage $ErrorDescription.$r
	}
	$InstallerVersion = (Get-Command "$WorkingDirectory\$Installer").FileVersionInfo.FileVersion
	Write-Log "InstallerVersion: $InstallerVersion" -FunctionName 'Prerequisites'
	If ([version]$InstallerVersion -lt [version]$DisplayVersion) {
		# Installer Version Mismatch
		$r = 99
		Abort-Script $ErrorDescription.$r -ExitCode $r -UserMessage $ErrorDescription.$r
	}
}

<# -- End Running Processes -- #>
If (!$RemotePC -and ((($TerminateWhen -in 'Uninstall','Both') -and $Uninstall) -or (($TerminateWhen -in 'Install','Both') -and !$Uninstall))) {
	Is-Running -Processes $TerminateProcesses -Stop | Out-Null
}

<# -- Add WMI Classes and Class Instances -- #>
If (!$RemotePC -and !$Uninstall) {
	$pArgumentList = 'ExtendedStatus.mof'
	Run-Process -FilePath 'C:\Windows\System32\wbem\mofcomp.exe' -Arguments $pArgumentList -WorkingDirectory "$Env:ProgramFiles\Microsoft Policy Platform" -EnableLogFile | Out-Null
}

Write-Log $EndTag -FunctionName 'Prerequisites'
#endregion Prerequisites

#region Uninstall
If (!$RemotePC -and ($Uninstall -Or $RemoveBeforeInstall)) {
	Write-Log $StartTag -FunctionName 'Uninstall'
	
	<# -- Default Return Value -- #>
	$r = 1605
	
	<# -- Allow MSI Upgrade -- #>
	If ($AllowUpgrade -And !$Uninstall) {
		$ExcludeProductCodes = Get-UpgradeKeys -Code $UpgradeCode
	}

	<# -- Base CommandLine to Uninstall All MSI DisplayName -- #>
	Get-UninstallKeys -DisplayName $UninstallDisplayName -ExcludeNames $ExcludeDisplayNames -ExcludeVersions $ExcludeDisplayVersions -ExcludeCodes $ExcludeProductCodes | ForEach-Object {
		$r = Remove-MSI $_
	}

	<# -- Base CommandLine for MSI Uninstallers -- #>
	#If ($ProductCode -notIn $ExcludeProductCodes) {
	#	$r = Remove-MSI -MSIProductCode $ProductCode
	#}

	<# -- Base CommandLines for Installshield Uninstallers -- #>
	#If (Test-Path "$ProgramFolder\Installshield Installation Information\$ProductCode\setup.exe") {
	#	$UArgumentList = "-runfromtemp -removeonly -s -f1`"$PSScriptRoot\$IssUninstall`" -f2`"$LogFolder\$($DisplayName)_$($DisplayVersion)-Uninstall.log`""
	#	$UArgumentList_x64 = "-runfromtemp -removeonly -s -f1`"$PSScriptRoot\$IssUninstall`" -f2`"$LogFolder\$($DisplayName)_$($DisplayVersion)_x64-Uninstall.log`""
	#	$r = Run-Process -FilePath "$ProgramFolder\Installshield Installation Information\$ProductCode\setup.exe" -Arguments $UArgumentList
	#	If ($Installx64Andx86 -and (Test-Path "$($Env:ProgramFiles)\Installshield Installation Information\$ProductCode\setup.exe")) {$r = Run-Process -FilePath "$($Env:ProgramFiles)\Installshield Installation Information\$ProductCode\setup.exe" -Arguments $UArgumentList_x64}
	#}

	<# -- Post Uninstall Tasks -- #>
	#New-RegistryKey -KeyPath <Registry_Key> -Name <Name> -PropertyType <PropertyType> -Value <Value>
	#New-RegistryKey -KeyPath <Registry_Key_Relative_Path> -Name <Name> -PropertyType <PropertyType> -Value <Value> -User
	#Remove-RegistryKey -KeyPath <Registry_Key> -Name <Name>
	#Remove-RegistryKey -KeyPath <Registry_Key_Relative_Path> -Name <Name> -User
	#Remove-RegistryKey -KeyPath "$SoftwareKey\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
	
	$Files = @(
		"$($Env:SystemRoot)\SMSCFG.ini",
		"$($Env:TEMP)\IPAddress.ini",
		"$($Env:TEMP)\ATSNResult.txt",
		"$($Env:TEMP)\SCCM_SITES.ini",
		"$($Env:SystemRoot)\Temp\IPAddress.ini",
		"$($Env:SystemRoot)\Temp\ATSNResult.txt",
		"$($Env:SystemRoot)\Temp\SCCM_SITES.ini"
	)
	ForEach ($File in $Files) {
		If (Test-Path $File) {
			Write-Log "Delete $File"
			Remove-Item $File -Force
		}
	}
	
	<# -- Copy Log(s) from TEMP -- #>
	If (($ReturnValue -ne "1605") -and ($CopyWhen -in 'Uninstall','Both')) {
		ForEach ($LogFileFromTemp In $UninstLogFromTemp) {
			Copy-LogFromTemp -fTempLogFile $LogFileFromTemp -fTempLogFolder $TempLogFolder -fUninstall
		}
	}
	
	<# -- Remove Shortcut -- #>
	#Remove-Shortcut -ShortcutName <Shortcut_Path> | Out-Null

	If ($r -eq 1605) {$r = 0}
	If ($r -eq 3010) {$RebootRequired = $True}
	Write-Log $EndTag -FunctionName 'Uninstall'
} 
#endregion Uninstall

#region Install
If (!$Uninstall -and !$RemotePC) {
	Write-Log $StartTag -FunctionName 'Install'
	
	<# -- Base CommandLine for MSI Installers -- #>
	#$r = New-MSI -Installer $Installer -Transform $Transform
	#If ($Installx64Andx86) {$r = New-MSI -Installer $Installer_x86 -Transform $Transform_x86}

	<# -- Base CommandLine for Installshield Installers -- #>
	#$iArgumentList = "-s -f1`"$PSScriptRoot\$IssFile`" -f2`"$LogFolder\$($DisplayName)_$($DisplayVersion)-Install.log`""				# Classic Installshield Arguments
	#$iArgumentList_x86 = "-s -f1`"$PSScriptRoot\$IssFile_x86`" -f2`"$LogFolder\$($DisplayName)_$($DisplayVersion)_x86-Install.log`""	# Classic Installshield Arguments (Both Only)
	#$iArgumentList = "/S /V`"/QN /NORESTART /L* \`"$LogFolder\$($DisplayName)_$($DisplayVersion)-Install.log\`"`""						# MSI-Based Installshield Arguments
	$iArgumentList = "/usepkicert /nocrlcheck /source:`"$($WorkingDirectory)`" /mp:https://vm0pwscpsa0002.corp.chartercom.com;https://vm0pwscpsa0003.corp.chartercom.com;https://vm0pwscpsa0004.corp.chartercom.com SMSSITECODE=AUTO SITEREASSIGN=TRUE FSP=vm0pwscpsa0005.corp.chartercom.com"
	$r = Run-Process -FilePath "$WorkingDirectory\$Installer" -Arguments $iArgumentList -WorkingDirectory $WorkingDirectory
	If ($Installx64Andx86) {$r = Run-Process -FilePath $Installer_x86 -Arguments $iArgumentList_x86}
	
	Do {
		Write-Log 'Waiting for installation process to complete' -FunctionName 'Install'
		Start-Sleep -s 30
	} Until (!(Is-Running $Installer))

	<# -- Post Install Tasks -- #>
	#New-Shortcut -ShortcutName <Shortcut_Path> -TargetPath <Target_Path> -Arguments <Arguments> -Icon <Icon> -Description <Description> -WorkingDirectory <Working_Directory>
	#New-Shortcut -ShortcutName <Shortcut_Path> -TargetPath <Target_Path> -Arguments <Arguments> -Icon <Icon> -Description <Description> -WorkingDirectory <Working_Directory> -NoTargetValidation
	
	#New-RegistryKey -KeyPath <Registry_Key> -Name <Name> -PropertyType <PropertyType> -Value <Value>
	#New-RegistryKey -KeyPath <Registry_Key_Relative_Path> -Name <Name> -PropertyType <PropertyType> -Value <Value> -User
	#Remove-RegistryKey -KeyPath <Registry_Key> -Name <Name>
	#Remove-RegistryKey -KeyPath <Registry_Key_Relative_Path> -Name <Name> -User
	#Setup-AddRemovePrograms -ProductCode $ProductCode -DisplayName $DisplayName -DisplayVersion $DisplayVersion -DisplayIcon <Icon> -EstimatedSize <Estimated_Size_in_KB> -Publisher <Publisher> -CreateInstallerCache
	
	ForEach ($File in $Files) {
		If (Test-Path $File) {
			Write-Log "Delete $File"
			Remove-Item $File -Force
		}
	}
	
	If (($r -eq 7) -or $RebootRequired) {$r = 3010}
	If ($r -in $SuccessCodes) {
		Remove-Folder -FolderName "$($Env:ProgramData)\Support\SCCMClient"
	}
	
	<# -- Copy Log(s) from TEMP -- #>
	If ($CopyWhen -in 'Install','Both') {
		ForEach ($LogFileFromTemp In $LogFromTemp) {
			Copy-LogFromTemp -fTempLogFile $LogFileFromTemp -fTempLogFolder $TempLogFolder
		}
	}
	<# -- Remove Desktop Shortcuts -- #>
	If ($RemoveDesktopShortcut) {
		ForEach ($DesktopShortcutFile In $DesktopShortcut) {
			Remove-Shortcut -ShortcutName $DesktopShortcutFile -Desktop	| Out-Null
		}
	}
	<# -- Remove Start Menu Shortcuts -- #>
	If ($RemoveStartMenuShortcut) {
		ForEach ($StartMenuShortcutFile In $StartMenuShortcut) {
			Remove-Shortcut -ShortcutName $StartMenuShortcutFile -StartMenu -Recurse | Out-Null
		}
	}
	<# -- Remove Pinned Taskbar Shortcuts -- #>
	If ($RemovePinnedShortcut) {
		ForEach ($PinnedShortcutFile In $PinnedShortcut) {
			Remove-Shortcut -ShortcutName $PinnedShortcutFile -Pinned | Out-Null
		}
	}

	Write-Log $EndTag -FunctionName 'Install'
}
#endregion Install

#endregion----------------[ Script ]-------------------------------------------------------------

#region----------------[ Script Exit ]-----------------------------------------------------------

If (!$RemotePC) {Write-Log "EXITCODE: $r"}
Write-Log "$Action Complete"
If (!$RemotePC) {[System.Environment]::Exit($r)}

#endregion----------------[ Script Exit ]--------------------------------------------------------
