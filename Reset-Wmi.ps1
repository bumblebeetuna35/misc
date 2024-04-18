<#

============================================================
	Reset WMI
============================================================
Date: 	03/21/2024
Author:	Matt Coons
============================================================
Script Details: Powershell.exe -File Reset-Wmi.ps1 [-SkipMessage] [-AdvancedRepair]

	Resets WMI
	
	This includes the following tasks:
		Basic Repair (Default):
			-Re-registers WMI Provider Services
			-CCM Repair
			-Machine Policy Retrieval/Evaluation and Hardware Inventory Cycles
			-Re-compiles:
				-ExtendedStatus.mof
				-Specific frequently broken WMI Classes ($BrokenClasses array)
				-All CCM WMI Classes (if present)
		Advanced Repair:
			-All tasks above
			-Re-register scecli.dll,userenv.dll
			-Re-compile all WMI Classes and Class Instances
		Logging:
			-Writes script log to %ProgramData%\Support\SoftwareInstall
			-Writes individual command logs to %ProgramData%\Support\WMI, where applicable
			
			
	Good reference material:
	https://techcommunity.microsoft.com/t5/blogs/blogarticleprintpage/blog-id/AskPerf/article-id/587

Parameters:
	-SkipMessage		= Do not display informational Message
	-AdvancedRepair		= Perform an advanced WMI repair (Slower)

#>

Param (
	[switch]$SkipMessage,
	[switch]$AdvancedRepair
)

$DisplayVersion = '2024.04.17'

# Trigger Schedule Ids
$MachinePolicyId = '{00000000-0000-0000-0000-000000000021}'
$HardwareInvId = '{00000000-0000-0000-0000-000000000001}'

# Trigger Schedule Timeout
$TimeOutMinutes = 60

# Registry Marker
$RegistryMarkerKey = "HKLM:\SOFTWARE\Chartercom\WMI_Repair"

# Frequenct Broken WMI Classes (Edit if necessary to target specific class(es))
$BrokenClasses = @(
	'Win32_ComputerSystem',
	'Win32_SystemEnclosure',
	'MSFT_Disk',
	'Win32_EncryptableVolume'
)

# Mofcomp Result Codes
$MofResultDescription = @{
	0 = 'SUCCESS';
	1 = 'FAILURE (The MOF compiler could not connect with the WMI server)';
	2 = 'FAILURE (One or more command-line switches were not valid)';
	3 = 'FAILURE (A MOF syntax error occurred)'
}

# Logging
$LogFolder = "$($Env:ProgramData)\Support\SoftwareInstall"
$WmiFolder = "$($Env:ProgramData)\Support\WMI"
$StartTag = "-------- Start -------->"
$EndTag =   "--------- End --------->"

Function Repair-Wmi {
	Param (
		[switch]$AdvancedRepair,
		$LogFolder = "$($Env:ProgramData)\Support\SoftwareInstall"
	)
	
	Write-Log $StartTag -FunctionName $MyInvocation.MyCommand.Name
	Write-Log "AdvancedRepair: $AdvancedRepair" -FunctionName $MyInvocation.MyCommand.Name
	
	$ServiceNames = @('Winmgmt','ccmexec')
	$Timer = 0
	$Mofcomp = "$Env:SystemRoot\System32\wbem\mofcomp.exe"
	$Retry = @()
	
	If (!(Test-Path $LogFolder)) {New-Item $LogFolder -ItemType Directory | Out-Null}

	Write-Log $StartTag -FunctionName 'Stop-Service'
	$Services = @(Get-Service | Where-Object {($_.Name -in $ServiceNames) -or ($_.DisplayName -in $ServiceNames)})
	$Services | Sort-Object | ForEach-Object {
		#Write-Log "Set-Service $($_.Name) -StartupType Disabled" -FunctionName 'Stop-Service'
		#Set-Service -InputObject $_ -StartupType 'Disabled'
		Write-Log $_.Name -FunctionName 'Stop-Service'
		Stop-Service -InputObject $_ -Force -ErrorAction SilentlyContinue
	}
	
	Get-Process | Where-Object {$_.Name -in $ServiceNames} | Sort-Object | ForEach-Object {
		Write-Log "Process Stop: $($_.Name)" -FunctionName 'Stop-Service'
		Stop-Process $_ -Force
		Start-Sleep -s 2
	}
	Get-Process | Where-Object {$_.Name -in $ServiceNames} | Sort-Object | ForEach-Object {
		Write-Log "Process Stop: $($_.Name)" -FunctionName 'Stop-Service'
		Stop-Process $_ -Force
		Start-Sleep -s 2
	}
	Write-Log $EndTag -FunctionName 'Stop-Service'
	
	Write-Log $StartTag -FunctionName 'Register WMI Providers'
	$RegserverFileNames = @('scrcons.exe','unsecapp.exe','wmiadap.exe','wmiapsrv.exe','wmiprvse.exe')
	ForEach ($SystemPath in "$Env:SystemRoot\System32","$Env:SystemRoot\SysWOW64") {
		Get-ChildItem "$SystemPath\wbem\*.exe" -Include $RegserverFileNames -Force | ForEach-Object {
			Write-Log "$($_.FullName) /regserver" -FunctionName 'Register WMI Providers'
			Start-Process -FilePath $_.FullName -ArgumentList '/regserver' -WorkingDirectory $_.Directory -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$LogFolder\$($_.Name)_$(Get-Date -Format 'yyyyMMdd-HHmmss').log" | Out-Null
		}
	}
	Write-Log $EndTag -FunctionName 'Register WMI Providers'

	Write-Log $StartTag -FunctionName 'WMI Repository'
	If ($AdvancedRepair) {
		Write-Log 'Rename repository' -FunctionName 'WMI Repository'
		Get-Item "$Env:Systemroot\System32\wbem\repository.old" -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse
		Get-Item "$Env:Systemroot\System32\wbem\repository" -ErrorAction SilentlyContinue | Rename-Item -NewName 'repository.old' -Force
	} Else {
		If ((Start-Process -FilePath 'Winmgmt' -ArgumentList '/resetrepository' -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$LogFolder\Winmgmt-reset_$(Get-Date -Format 'yyyyMMdd-HHmmss').log").ExitCode -eq 0) {
			Write-Log 'Reset Repository SUCCESS' -FunctionName 'WMI Repository'
		} Else {
			Write-Log 'Reset Repository FAILURE' -FunctionName 'WMI Repository'
		}
		If ((Start-Process -FilePath 'Winmgmt' -ArgumentList '/salvagerepository' -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$LogFolder\Winmgmt-salvage_$(Get-Date -Format 'yyyyMMdd-HHmmss').log").ExitCode -eq 0) {
			Write-Log 'Salvage Repository SUCCESS' -FunctionName 'WMI Repository'
		} Else {
			Write-Log 'Salvage Repository FAILURE' -FunctionName 'WMI Repository'
		}
	}
	Write-Log $EndTag -FunctionName 'WMI Repository'
	
	If ($AdvancedRepair) {
		Write-Log $StartTag -FunctionName 'Register DLL'
		$DllFiles = @('scecli.dll','userenv.dll')
		Get-ChildItem "$Env:SystemRoot\System32\*.dll" -Include $DllFiles -Force | ForEach-Object {
			Write-Log $_.Name -FunctionName 'Register DLL'
			Start-Process -FilePath 'regsvr32' -ArgumentList "/s $($_.FullName)" -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$LogFolder\$($_.Name)_$(Get-Date -Format 'yyyyMMdd-HHmmss').log" | Out-Null
		}
		Write-Log $EndTag -FunctionName 'Register DLL'
	}
	
	If ($AdvancedRepair) {
		Write-Log $StartTag -FunctionName 'WMI Classes/Instances'
		$MofFiles = @('cimwin32.mof','cimwin32.mfl','rsop.mof','rsop.mfl')
		Get-ChildItem "$Env:SystemRoot\System32\wbem\*.*" -Include $MofFiles -Force | ForEach-Object {
			$r = (Start-Process -FilePath $Mofcomp -ArgumentList $_.Name -WorkingDirectory $_.Directory -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$LogFolder\$($_.Name)_$(Get-Date -Format 'yyyyMMdd-HHmmss').log").ExitCode
			Write-Log "($r) $($MofResultDescription.$r) - $($_.Name)" -FunctionName 'WMI Classes/Instances'
			If ($r -ne 0) {$Retry += $_}
		}
		Write-Log $EndTag -FunctionName 'WMI Classes/Instances'
	}
	
	If ($AdvancedRepair) {
		Write-Log $StartTag -FunctionName 'Register DLL'
		Get-ChildItem "$Env:SystemRoot\System32\wbem\*.dll" -Force | ForEach-Object {
			Write-Log $_.Name -FunctionName 'Register DLL'
			Start-Process -FilePath 'regsvr32' -ArgumentList "/s `"$($_.FullName)`"" -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$LogFolder\$($_.Name)_$(Get-Date -Format 'yyyyMMdd-HHmmss').log" | Out-Null
		}
		Write-Log $EndTag -FunctionName 'Register DLL'
		
		Write-Log $StartTag -FunctionName 'Process MOF'
		ForEach ($SystemPath in "$Env:SystemRoot\System32","$Env:SystemRoot\SysWOW64") {
			Get-ChildItem "$SystemPath\wbem\*.*" -Include '*.mof','*.mfl' -Exclude $MofFiles -Force | Where-Object {($_.Name -notlike '*uninstall*') -and ($_.Name -notlike '*remove*')} | ForEach-Object {
				$r = (Start-Process -FilePath $Mofcomp -ArgumentList "`"$($_.FullName)`"" -WorkingDirectory $_.Directory -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$LogFolder\$($_.Name)_$(Get-Date -Format 'yyyyMMdd-HHmmss').log").ExitCode
				Write-Log "($r) $($MofResultDescription.$r) - $($_.Name)" -FunctionName 'Process MOF'
				If ($r -ne 0) {$Retry += $_}
			}
		}
		Write-Log $EndTag -FunctionName 'Process MOF'
	}
	
	Write-Log $StartTag -FunctionName 'Microsoft Policy Platform'
	$PPMofFiles = @('SchemaNamespaces.mof','ExtendedStatus.mof')
	Get-ChildItem "$Env:ProgramFiles\Microsoft Policy Platform\*.mof" -Include $PPMofFiles | Sort-Object -Descending | ForEach-Object {
		$r = (Start-Process -FilePath $Mofcomp -ArgumentList $_.Name -WorkingDirectory $_.Directory -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$LogFolder\$($_.Name)_$(Get-Date -Format 'yyyyMMdd-HHmmss').log").ExitCode
		Write-Log "($r) $($MofResultDescription.$r) - $($_.Name)" -FunctionName 'Microsoft Policy Platform'
		If ($r -ne 0) {$Retry += $_}
	}
	Write-Log $EndTag -FunctionName 'Microsoft Policy Platform'
	
	If (Test-Path 'C:\Windows\CCM\ccmexec.exe') {
		Write-Log $StartTag -FunctionName 'Process CCM MOF'
		Get-ChildItem "$Env:SystemRoot\CCM\*.*" -Include '*.mof','*.mfl' -Force -ErrorAction SilentlyContinue | Where-Object {$_.BaseName -notmatch '_inst'} | ForEach-Object {
			$r = (Start-Process -FilePath $Mofcomp -ArgumentList "`"$($_.FullName)`"" -WorkingDirectory $_.Directory -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$LogFolder\$($_.Name)_$(Get-Date -Format 'yyyyMMdd-HHmmss').log").ExitCode
			Write-Log "($r) $($MofResultDescription.$r) - $($_.Name)" -FunctionName 'Process CCM MOF'
			If ($r -ne 0) {$Retry += $_}
		}
		Write-Log $EndTag -FunctionName 'Process CCM MOF'
	}
	
	If ($Retry.Count -gt 0) {
		Write-Log $StartTag -FunctionName 'Retry Failed MOF'
		$Retry | ForEach-Object {
			$r = (Start-Process -FilePath $Mofcomp -ArgumentList "`"$($_.FullName)`"" -WorkingDirectory $_.Directory -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$LogFolder\$($_.Name)_$(Get-Date -Format 'yyyyMMdd-HHmmss').log").ExitCode
			Write-Log "($r) $($MofResultDescription.$r) - $($_.Name)" -FunctionName 'Retry Failed MOF'
		}
		Write-Log $EndTag -FunctionName 'Retry Failed MOF'
	}

	Write-Log $StartTag -FunctionName 'Start-Service'
	$Services | Sort-Object -Descending | ForEach-Object {
		Write-Log "Set-Service $($_.DisplayName) -StartupType Automatic" -FunctionName 'Start-Service'
		Set-Service -InputObject $_ -StartupType 'Automatic'
		If ($_.Name -eq 'ccmexec') {
			Write-Log "Set-Service $($_.DisplayName) -StartupType AutomaticDelayedStart" -FunctionName 'Start-Service'
			New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)" -Name 'Start' -Value 2 -PropertyType 'Dword' -Force | Out-Null
		}
		If ($_.Name -eq 'Winmgmt') {
			Write-Log $_.DisplayName -FunctionName 'Start-Service'
			Start-Service -InputObject $_ -ErrorAction SilentlyContinue
		}
	}
	Write-Log $EndTag -FunctionName 'Start-Service'
	
	# Write Marker
	New-Item -Path $RegistryMarkerKey -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty -Path $RegistryMarkerKey -Name 'LastRepair' -Value "$(Get-Date -f "MM/dd/yyyy HH:mm:ss")" -Force | Out-Null
	New-ItemProperty -Path $RegistryMarkerKey -Name 'RepairType' -Value "$(If ($AdvancedRepair) {'Advanced'} Else {'Standard'})" -Force | Out-Null

	If (Test-Path 'C:\Windows\CCM\ccmrepair.exe') {
		Write-Log $StartTag -FunctionName 'Repair CCM Client'
		
		Start-Process -FilePath 'C:\Windows\CCM\ccmrepair.exe' -NoNewWindow -Wait -RedirectStandardOutput "$LogFolder\ccmrepair_$(Get-Date -Format 'yyyyMMdd-HHmmss').log" | Out-Null
		Start-Sleep -s 10

		Write-Log 'Trigger CCM Machine Policy Retrieval' -FunctionName 'Repair CCM Client'
		$MachinePolicyResult = Try {Invoke-CimMethod -Namespace 'root\CCM' -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{sScheduleID=$MachinePolicyId} -ErrorAction SilentlyContinue} Catch {}
		If ($MachinePolicyResult) {
			Write-Log 'CCM Machine Policy SUCCESS' -FunctionName 'Repair CCM Client'
			
			Do {
				Write-Log 'Trigger CCM Hardware Inventory' -FunctionName 'Repair CCM Client'
				$HardwareInvResult = Try {Invoke-CimMethod -Namespace 'root\CCM' -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{sScheduleID=$HardwareInvId} -ErrorAction SilentlyContinue} Catch {}
				If (!$HardwareInvResult) {
					$Timer++
					Write-Log 'CCM Hardware Inventory NOT READY' -FunctionName 'Repair CCM Client'
					Write-Log  'Retry in 60 seconds...' -FunctionName 'Repair CCM Client'
					Start-Sleep -s 60
				}
			} Until ($HardwareInvResult -or ($Timer -ge $TimeOutMinutes))
			If ($HardwareInvResult) {
				Write-Log 'CCM Hardware Inventory SUCCESS' -FunctionName 'Repair CCM Client'
			} Else {
				Write-Log 'CCM Hardware Inventory FAILURE' -FunctionName 'Repair CCM Client'
			}
		} Else {
			Write-Log 'CCM Machine Policy FAILURE' -FunctionName 'Repair CCM Client'
		}
		
		$CcmReinstallRequired = $False
		Write-Log $EndTag -FunctionName 'Repair CCM Client'
	} Else {
		$CcmReinstallRequired = $True
		Write-Log 'CCM Client NOT FOUND: Please reinstall' -FunctionName $MyInvocation.MyCommand.Name
	}
	
	$CcmReinstallRequired
	Write-Log $EndTag -FunctionName $MyInvocation.MyCommand.Name
}

Function Repair-SpecificClass {
	Param (
		[string[]]$Classes
	)
	
	Write-Log $StartTag -FunctionName $MyInvocation.MyCommand.Name
	Write-Log "Classes: $($Classes -join ', ')" -FunctionName $MyInvocation.MyCommand.Name
	
	$MofFiles = @()
	$Results = @()
	$Mofcomp = "$Env:SystemRoot\System32\wbem\mofcomp.exe"

	ForEach ($Class in $Classes) {
		Get-ChildItem 'C:\Windows\System32\wbem\*.mof' | ForEach-Object {
			$MofContent = Get-Content $_.FullName
			If (($MofContent -match "^class $($Class) :") -or ($MofContent -match "^class $($Class)$")) {
				$MofFiles += New-Object PSObject -Property @{
					Class = $Class
					Name = $_.Name
					FullName = $_.FullName
					Directory = $_.Directory
				}
			}
		}
	}

	$MofFiles | Sort-Object 'Name' | ForEach-Object {
		If ($_.Name -notin $Results.Name) {
			Write-Log "Compile: $($_.Name) ($($_.Class))" -FunctionName $MyInvocation.MyCommand.Name
			$r = (Start-Process -FilePath $Mofcomp -ArgumentList $_.Name -WorkingDirectory $_.Directory -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$LogFolder\$($_.Name)_$(Get-Date -Format 'yyyyMMdd-HHmmss').log").ExitCode
		} Else {
			Write-Log "Skip: $($_.Name) ($($_.Class))" -FunctionName $MyInvocation.MyCommand.Name
			$r = ($Results | Where-Object {$_.Name -eq $Results.Name} | Select-Object -First 1).Result
		}
		$Results += New-Object PSObject -Property @{
			Class = $_.Class
			Name = $_.Name
			FullName = $_.FullName
			Directory = $_.Directory
			Result = $r
		}
	}

	$Results | ForEach-Object {
		Write-Log "($($_.Result)) $($MofResultDescription.($_.Result)) - $($_.Class) ($($_.Name))" -FunctionName $MyInvocation.MyCommand.Name
	}
	
	Write-Log $EndTag -FunctionName $MyInvocation.MyCommand.Name
}

Function Clean-LogFiles {
	Param (
		$LogFolder = "$($Env:ProgramData)\Support\SoftwareInstall",
		[int]$SizeLessEqualToKb = 0
	)
	
	Write-Log $StartTag -FunctionName $MyInvocation.MyCommand.Name
	Write-Log "LogFolder: $LogFolder" -FunctionName $MyInvocation.MyCommand.Name
	Write-Log "SizeLessEqualToKb: $SizeLessEqualToKb KB" -FunctionName $MyInvocation.MyCommand.Name
	
	Get-ChildItem "$WmiFolder\*.log" | Where-Object {($_.Length/1KB) -eq $SizeLessEqualToKb} | ForEach-Object {
		Write-Log "$($_.Name) ($("{0:n1}" -f ($_.Length/1KB)) KB)" -FunctionName $MyInvocation.MyCommand.Name
		Remove-Item $_ -Force | Out-Null
	}
	
	Write-Log $EndTag -FunctionName $MyInvocation.MyCommand.Name
}

Function Write-Log {
	<#
		.SYNOPSIS
			Writes messages to a log file
		.DESCRIPTION
			Writes messages to the a log file with or without a timestamp. Requires that the Create-Log function was called with the filename.
		.PARAMETER Message
			The message that needs to be written.
		.PARAMETER NoTimestamp
			Removes the timestamp from the log message
		.PARAMETER FunctionName
			Allows you to include the name of a function as part of the message
		.PARAMETER Filename
			Sets the file to log to. If path is not specified, will use the default path.
		.PARAMETER ClearLog
			Deletes a pre-existing log file.
		.PARAMETER Archive
			Will Archive an existing log file if it exceeds 500KB.
		.HISTORY
			2019-11-04 Matt Coons
				Disable console output if NoConsoleOutput switch is specified
				Disable log if DetectionRuleOnly is specified
			2018-03-23 Donald Butler
				Original Version of the function.
	#>

	Param (
		[Parameter(Mandatory=$True,ValueFromPipeline=$True)][AllowEmptyString()][string]$Message,
		$FunctionName,
		$Filename,
		[switch]$NoTimestamp,
		[switch]$ClearLog,
		[switch]$Archive
	)
	If (!$DetectionRuleOnly) {

		If ($Filename) {
			If ((Split-Path $Filename -Parent) -eq '') {
				$Script:ScriptLog = "$LogFolder\$Filename"
			} Else {
				$Script:ScriptLog = $Filename
			}
			If ($Archive -and (Test-Path $ScriptLog)) {
				$f = Get-Item $ScriptLog
				If ($f.Length -gt 500KB) {
					Move-Item $ScriptLog -Destination "$($f.DirectoryName)\$($f.Basename)-Archive$($f.Extension)" -Force
				}
			}
		}
		
		$MessageString = "$(If(!$NoTimestamp){"[ $(Get-Date) ] "})$(If($FunctionName){"$($FunctionName): "})$Message"
		If (!$NoConsoleOutput) {Write-Host $MessageString}

		If ($ScriptLog) {
			If (!(Test-Path (Split-Path $ScriptLog -Parent))) {New-Item (Split-Path $ScriptLog -Parent) -ItemType Directory | Out-Null}
			If ($ClearLog -And (Test-Path $ScriptLog)) {
				Remove-Item $ScriptLog -Force
			}
			Out-File -FilePath $ScriptLog -Append -Width 1000 -InputObject $MessageString
		}
	}
	
}

Write-Log "--------------------------------$(If (!$AdvancedRepair) {'Basic'} Else {'Advanced'}) WMI Repair-------------------------------------------------" -Filename "Reset-Wmi.log" -NoTimestamp -Archive

$Message = @"
WMI REPAIR - READ BEFORE PROCEEDING!

This script:
1. Performs a$(If (!$AdvancedRepair) {' basic'} Else {'n advanced'}) repair of WMI
2. Re-compiles ExtendedStatus.mof
3. Re-compiles these classes: $($BrokenClasses -join ', ')
4. Repairs the CCM Client (and Software Center), if fully installed
5. Re-compiles all CCM Client classes, if present
6. Triggers Machine Policy Evaluation and Hardware Inventory Cycles
7. Logs all commands to $WmiFolder
8. Writes a script log to $LogFolder

This script DOES NOT:
1. Install the CCM Client; If not installed, it must be (re)installed once this script completes.

IMPORTANT:
 -If a basic repair does not fully resolve WMI issues, please re-run this script using the -AdvancedRepair parameter.
 -Seeing `"Process MOF`" and `"Process CCM MOF`" failures are normal during the repair.

"@

If (!$SkipMessage) {
	Write-Log 'Show User Message'
	Clear-Host
	Write-Host $Message
	PAUSE
	Write-Log 'User Message Acknowledged'
} Else {
	Write-Log 'Skip User Message'
}

$CcmClientInstallRequired = If ($AdvancedRepair) {
	Repair-Wmi -AdvancedRepair -LogFolder $WmiFolder
} Else {
	Repair-Wmi -LogFolder $WmiFolder
}

Repair-SpecificClass -Classes $BrokenClasses
Clean-LogFiles -LogFolder $WmiFolder -SizeLessEqualToKb 0

$r = &Winmgmt /verifyrepository
Write-Log $r
Write-Log "-SCRIPT COMPLETE-$(If ($CcmClientInstallRequired) {"`nATTENTION: CCM Client must be reinstalled!"})"
