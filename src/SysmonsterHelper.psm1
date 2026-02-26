using namespace System.Collections

class MenuMember
{
    [ValidateNotNullOrEmpty()][string]$Title
    [ValidateNotNullOrEmpty()][string]$Description
    [string]$Example
}

class Option
{
    [string]$Title
    [string]$Description
    [string]$State
}

class Event
{
    [ValidateNotNullOrEmpty()][int]$eid
    [ValidateNotNullOrEmpty()][arraylist]$Options
    [string]$attackVector
}

class SysmonVersion
{
    [string]$SysmonVersion
    [string]$SchemaVersion
    [byte[]]$ByteRule
}

$SYSMONSTER_PROMPT = "SYSMONSTER"
$PROMPT_ENDING = ">"
$PROMPT_SEPERATOR = "\"
$HELP_COMMANDS = @("help", "?", "h", "menu")
$SysmonCommand = ""
$Sysmonster_tag = @()
$Sysmonster_tag += $SYSMONSTER_PROMPT
$events = @()
$Global:isConfFileSet = $false
$Global:state = $null
$Global:ArchiveDirectory = ""
$Global:log = $false
$Global:origRuleBytes = [byte[]]@()

$EventDic = @{
    "ProcessCreate"          = 1  ;
    "FileCreateTime"         = 2  ;
    "NetworkConnect"         = 3  ;
    "ProcessTerminate"       = 5  ;
    "DriverLoad"             = 6  ;
    "ImageLoad"              = 7  ;
    "CreateRemoteThread"     = 8  ;
    "RawAccessRead"          = 9  ;
    "ProcessAccess"          = 10 ;
    "FileCreate"             = 11 ;
    "RegistryEvent"          = 12 ;
    "FileCreateStreamHash"   = 15 ;
    "PipeEvent"              = 17 ;
    "WmiEvent"               = 19 ;
    "DnsQuery"               = 22 ;
    "FileDelete"             = 23 ;
    "ClipboardChange"        = 24 ;
    "ProcessTampering"       = 25 ;
    "FileDeleteDetected"     = 26 ;
    "FileBlockExecutable"    = 27 ;
    "FileBlockShredding"     = 28 ;
    "FileExecutableDetected" = 29 ;
};

# Initialize Sysmon versions from JSON database
function Initialize-SysmonVersionDatabase
{
	<#
	.SYNOPSIS
	    Loads Sysmon version database from external JSON file on module import.

	.DESCRIPTION
	    Initializes the global $SysmonVersions array by reading a JSON database containing
	    Sysmon version information, schema versions, and byte rules for version detection.
	    This function is called automatically when the module loads.

	.OUTPUTS
	    [bool] Returns $true on success, $false on failure.

	.NOTES
	    - Requires JSON database file at: data\sysmon_versions.json
	    - Populates global variable: $Global:SysmonVersions
	    - Used by Invoke-SilentSysmonPolicy for version-based rule silencing
	#>
	try {
		$dataPath = Join-Path -Path $PSScriptRoot -ChildPath "..\data\sysmon_versions.json"
		
		if (-not (Test-Path -Path $dataPath)) {
			Write-Warning "Sysmon versions database file not found at: $dataPath"
			return $false
		}
		
		$jsonContent = Get-Content -Path $dataPath -Raw | ConvertFrom-Json
		$Global:SysmonVersions = @()
		
		foreach ($version in $jsonContent.versions) {
			$Global:SysmonVersions += [SysmonVersion]@{
				SysmonVersion = $version.sysmonVersion
				SchemaVersion = $version.schemaVersion
				ByteRule = [byte[]]@($version.byteRule)
			}
		}
		
		Write-Verbose "Successfully loaded $($Global:SysmonVersions.Count) Sysmon versions from database"
		return $true
	}
	catch {
		Write-Error "Failed to initialize Sysmon version database: $_"
		return $false
	}
}

$BasicRuleParseOption = [Option]@{
    Title = "Basic Check"
    Description = "xml rule parsing"
    State = "Offline"
}

$HighRuleParseOption = [Option]@{
    Title = "High Check"
    Description = "xml rule parsing and misconfigurations highlighting"
    State = "Online"
}

$EventObjList = @(

    [Event]@{
        eid = 1
        Options = @($BasicRuleParseOption, $HighRuleParseOption) + @(
            [Option]@{
                Title = "Write permissions check"
                Description = "For changing process file content (.exe) you need at least 'Write' permissions"
                State = "Online"
            },
            [Option]@{
                Title = "Execute permissions check"
                Description = "For executing your executable you need 'Execute' permissions"
                State = "Online"
            }
        )
        attackVector = @"
[*] If one of the parameters Image\ParentImage is excluded and an attacker has write permission on them,
    the binary might be switched to a malicious one and used by the attacker without being logged.
    
    For example:
    if the image on path C:\User\verySafeDirectory\myfile.exe is writeable, an attacker might switch it to his binary.
    if the parent image is writeable, whatever is running under it will be excluded.

[*] If one of the parameters CommandLine\ParentCommandLine is excluded and an attacker has write permission on the binary,
    the binary might be switched to a malicious one and used by the attacker without being logged.

    For example:
    if the command line "C:\User\verySafeDirectory\myfile.exe -m option" is excluded and the binary myfile.exe is writeable, 
    an attacker might switch it to his binary and use the command as it is written in the rule.
    if the parent command line is writeable, whatever is running under it will be excluded.
"@
    },

    [Event]@{
        eid = 2
        Options = @($BasicRuleParseOption, $HighRuleParseOption) + @(
            [Option]@{
                Title = "Write permissions check"
                Description = "For changing file timestamps you need at least 'Write' permissions"
                State = "Online"
            }
        )
        attackVector = @"
[*] As mentioned in MITRE Technique "TimeStomp" (T1070.006), a file which his timestamps (in our case, the "created" timestamp)
    are changed is not appear conspicuous to forensic investigators or file analysis tools.
    If an attacker has write permissions on an excluded file, he can change the "created" timestamp.
"@
    },

    [Event]@{
        eid = 3
        Options = @($BasicRuleParseOption, $HighRuleParseOption) + @(
            [Option]@{
                Title = "Write permissions check"
                Description = "For changing process file content (.exe) you need at least 'Write' permissions"
                State = "Online"
            },
            [Option]@{
                Title = "Execute permissions check"
                Description = "For executing your executable you need 'Execute' permissions"
                State = "Online"
            },
            [Option]@{
                Title = "External network check"
                Description = "Check for unsecure DNS queries & network elements"
                State = "Offline"
            }
        )
        attackVector = @"
[*] If an attacker has write permissions on an excluded binary, he can switch it to his own and any network connection it will make 
will be excluded
"@
    },

    [Event]@{
        eid = 5
        Options = @($BasicRuleParseOption)
    },

    [Event]@{
        eid = 6
        Options = @($BasicRuleParseOption) + @(
            [Option]@{
                Title = "Signature status check"
                Description = "check for signatures without 'SignatureStatus' validation"
                State = "Offline"
            }
        )
    },

    [Event]@{
        eid = 7
        Options = @($BasicRuleParseOption)
    },

    [Event]@{
        eid = 8
        Options = @($BasicRuleParseOption) + @(
            [Option]@{
                Title = "Create remote thread check"
                Description = "[*] For creating a remote thread, a handle of proccess must have the`nPROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, and PROCESS_VM_WRITE access rights"
                State = "Online"
            }
        )
    },

    [Event]@{
        eid = 9
        Options = @($BasicRuleParseOption)
    },

    [Event]@{
        eid = 10
        Options = @($BasicRuleParseOption)
    },

    [Event]@{
        eid = 11
        Options = @($BasicRuleParseOption, $HighRuleParseOption) + @(
            [Option]@{
                Title = "Write permissions check"
                Description = "For creating or modifying file you need at least 'Write' permissions"
                State = "Online"
            }
        )
        attackVector = @"
[*] If an attacker has write permissions on an excluded binary, he can switch it to his own and any file creation will be excluded.
"@
    },

    [Event]@{
        eid = 12
        Options = @($BasicRuleParseOption) + @(
            [Option]@{
                Title = "Interesting registry rules"
                Description = "Excluded registry objects could be used by the attacker (see more info inside the option)"
                State = "Online"
            },

            [Option]@{
                Title = "Object create"
                Description = "Registry object creation permissions check"
                State = "Online"
            },

            [Option]@{
                Title = "Object delete"
                Description = "Registry object deletion permissions check"
                State = "Online"
            },

            [Option]@{
                Title = "Value set"
                Description = "Registry value setting permissions check"
                State = "Online"
            },

            [Option]@{
                Title = "Key and Value rename"
                Description = "Registry key/value renaming permissions check"
                State = "Online"
            }
        )
        attackVector = @"
[*] If an attacker wants to store his own data in registry paths, excluded paths with exclude conditions like "end with" and "contains"
    may suit for his operation.
        
    For example:
    if the rule excludes all the paths that contains "\Microsoft\Windows", the attacker can create this path 
    under "HKLM\Attacker\Microsoft\Windows" and write to it without being logged.
    
[*] If an attacker wants to store his own data in registry paths, excluded paths with exclude conditions like "begins with" and with add value
    permission may suit for his operation. This vector can also be suitable for deleting his registry paths.
        
    For example:
    if the rule excludes all the paths that begins with "HKLM\Software\Microsoft\Windows\CurrentVersion\", the attacker can create the path 
    "HKLM\Software\Microsoft\Windows\CurrentVersion\Attacker" without being logged.
        
[*] If the "EventType" property is excluded, many operations might not be logged.
            
    For example:
    if the event type of "CreateKey" is excluded, every key the attacker will create will not be logged.
"@
    },

    [Event]@{
        eid = 15
        Options = @($BasicRuleParseOption, $HighRuleParseOption) + @(
            [Option]@{
                Title = "Write permissions check"
                Description = "For creating an alternate data stream you need at least 'Write' permissions"
                State = "Online"
            }
        )
        attackVector = @"
[*] As mentioned in MITRE Technique T1564.004, Alternate Data Streams (ADSs) can be used to store arbitrary data (or even complete files). 
    If an attacker has write permissions on an excluded file, he can write an alternate data strem and it will not be logged.
"@
    },

    [Event]@{
        eid = 17
        Options = @($BasicRuleParseOption)
    },

    [Event]@{
        eid = 19
        Options = @($BasicRuleParseOption)
    },

    [Event]@{
        eid = 22
        Options = @($BasicRuleParseOption, $HighRuleParseOption) + @(
            [Option]@{
                Title = "Unsecure DNS queries"
                Description = "Check for unsecure queries - queries that filtered by 'end with' condition but doesn't have '.' at the beggining of the query"
                State = "Offline"
            }
        )
        attackVector = @"
[*] If an attacker has write permissions on an excluded binary, he can switch it to his own and any DNS queries it will make 
will be excluded
"@
    },

    [Event]@{
        eid = 23
        Options = @($BasicRuleParseOption) + @(
            [Option]@{
                Title = "Delete permissions check"
                Description = "For deleting a file you need at least 'Delete' permissions"
                State = "Online"
            },
            [Option]@{
                Title = "Archive directory check"
                Description = "Users/Groups permission at Archive directory"
                State = "Online"
            }
        )
    },

    [Event]@{
        eid = 24
        Options = @($BasicRuleParseOption) + @(
            [Option]@{
                Title = "Archive directory check"
                Description = "Users/Groups permission at Archive directory"
                State = "Online"
            }
        )
    },

    [Event]@{
        eid = 25
        Options = @($BasicRuleParseOption)
    },

    [Event]@{
        eid = 26
        Options = @($BasicRuleParseOption) + @(
            [Option]@{
                Title = "Delete permissions check"
                Description = "For deleting a file you need at least 'Delete' permissions"
                State = "Online"
            }
        )
    },

    [Event]@{
        eid = 27
        Options = @($BasicRuleParseOption)
    },

    [Event]@{
        eid = 28
        Options = @($BasicRuleParseOption)
    },

    [Event]@{
        eid = 29
        Options = @($BasicRuleParseOption)
    }
)

$Menu_Title = "====================== SYSMONSTER COMMANDS ======================"
    
$Help_Command = [MenuMember]@{
    Title = "HELP/MENU/?/H`n============="
    Description = "Displays Sysmonster's help menu"
    Example = ""
}

$SetConf_Command = [MenuMember]@{
    Title = "SET CONF`n========"
    Description = "Sets a Sysmon xml config file"
    Example = "`nExample:`n`tSET CONF sysmon_conf.xml"
}

$SetState_Command = [MenuMember]@{
    Title = "SET STATE`n========="
    Description = @"
Sets state to online (for active checks on the machine)
or offline (for checks outside the machine) 
"@
    Example = "`nExample:`n`tSET STATE online`n`tSET STATE offline"
}

$SetLog_Command = [MenuMember]@{
    Title = "SET LOG`n======="
    Description = @"
Sets log option (on -> starts log, off -> stops log)
"@
    Example = "`nExample:`n`tSET LOG on`n`tSET LOG off"
}

$GetEventList_Command = [MenuMember]@{
    Title = "GET EVENTLIST`n============="
    Description = "Gets a list of Sysmon events"
    Example = "`nExample:`n`tGET EVENTLIST"
}

$SetEvent_Command = [MenuMember]@{
    Title = "SET EVENT`n========="
    Description = "Sets an event/s for Sysmonster's check"
    Example = @"
        `nExample:
        SET EVENT 1
        SET EVENT 3,6,8,10
        SET EVENT 5-22
        SET EVENT ALL -> for all events
"@
}

$ShowOptions_Command = [MenuMember]@{
    Title = "SHOW OPTIONS`n============"
    Description = "Displays options for a specific event (must run after an event is picked)"
    Example = "`nExample:`n`tSHOW OPTIONS"
}

$SetOption_Command = [MenuMember]@{
    Title = "SET OPTION`n=========="
    Description = @"
Sets a check for a specific event (must run after an event is picked)
Usually the first option will be the basic xml parsing, the second
will be parsing & misconfigurations highlighting and the others will be
advanced checks.
"@
    Example = "`nExample:`n`tSET OPTION 2"
}

$Silent_Command = [MenuMember]@{
    Title = "SILENT`n======"
    Description = "Silence Sysmon policy by putting empty policy in the registry"
    Example = "`nExample:`n`tSILENT"
}

$Revert_Command = [MenuMember]@{
    Title = "REVERT`n======="
    Description = "Revert Sysmon policy by putting the original policy in the registry"
    Example = "`nExample:`n`tREVERT"
}

$Run_Command = [MenuMember]@{
    Title = "RUN`n==="
    Description = "Runs the option picked to the event."
    Example = "`nExample:`n`tRUN"
}

$Next_Command = [MenuMember]@{
    Title = "NEXT`n===="
    Description = "Continue to the next event."
    Example = "`nExample:`n`tNEXT"
}

$Exit_Command = [MenuMember]@{
    Title = "EXIT`n===="
    Description = "exits from script."
    Example = "`nExample:`n`tEXIT"
}

$mainMenu = @(
    $Help_Command,
    $SetConf_Command,
    $SetState_Command,
    $SetLog_Command,
    $GetEventList_Command,
    $SetEvent_Command,
    $ShowOptions_Command,
    $SetOption_Command,
    $Silent_Command,
    $Revert_Command,
    $Run_Command,
    $Exit_Command
)

$secondaryMenu = @(
    $Help_Command,
    $ShowOptions_Command,
    $SetOption_Command,
    $Run_Command,
    $Next_Command,
    $Exit_Command
)

function Show-Menu
{
    param(
        [Parameter(Mandatory=$true)]$Menu
    )
    Write-Message -Message $Menu_Title -Color "Green"
    
    foreach ($MenuMember in $Menu)
    {
        Write-Host
        Write-Message -Message $MenuMember.Title -Color "DarkCyan"
        Write-Message -Message $MenuMember.Description -Color "White"
        Write-Message -Message $MenuMember.Example -Color "White"
        Write-Host
    }
}

function Invoke-SysmonsterCLI
{
	<#
	.SYNOPSIS
	    Main interactive CLI entry point for Sysmonster analysis framework.

	.DESCRIPTION
	    Launches the interactive command-line interface for Sysmonster's framework. Detects installed Sysmon
	    configuration, retrieves version information, and provides an interactive menu for analyzing
	    Sysmon event rules, and managing Sysmon policies.
	    Supports both online (active checking on local machine) and offline modes.

	.OUTPUTS
	    Interactive CLI with menu-driven analysis of Sysmon configurations.

	.NOTES
	    - Requires administrator privileges for certain operations
	    - Available commands: SET CONF, SET STATE, SET EVENT, SET OPTION, RUN, SILENT, REVERT, EXIT
	#>
    try {
        $confFile = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" -Name "ConfigFile" -ErrorAction Stop).ConfigFile
        Write-SuccessMessage -Message "[+] Found Sysmon config file: $confFile"
    }

    catch { Write-ErrorMessage -Message '[!] Error while trying to find config path, try open as Admin (or maybe Sysmon in not running)' }
    
    try {
        $sysmonPath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon" -Name "ImagePath" -ErrorAction Stop).ImagePath
        if (Test-Path -Path $sysmonPath) { Write-InfoMessage -Message "[*] Sysmon binary path: $sysmonPath" }
        else { Write-ErrorMessage -Message "[!] Cannot find Sysmon binary path" }
    }
    catch {
        Write-ErrorMessage -Message '[!] Error while trying to find Sysmon binary path, try open as Admin (or maybe Sysmon in not running)'
    }

    if ($sysmonPath) { 
        $sysmonVersion = (Get-ItemProperty -Path $sysmonPath -Name VersionInfo -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
    }
    if ($sysmonVersion) 
    {
        Write-InfoMessage -Message "[*] Sysmon Version: $sysmonVersion" 
        $SchemaVersion = ($SysmonVersions | Where-Object { $_.SysmonVersion -eq $sysmonVersion } | Select-Object SchemaVersion).SchemaVersion
        if ($SchemaVersion) { Write-InfoMessage -Message "[*] Schema Version: $SchemaVersion" }
    }
    else { Write-ErrorMessage -Message "[!] Unable to find Sysmon version" }

    Write-Host `n`n

    while ($SysmonCommand -ne "exit")
    {
        $SysmonCommand =  Read-SysmonCommand -Prompt $Sysmonster_tag
        
        switch ($SysmonCommand)
        {
            { $HELP_COMMANDS -contains $_ } { Show-Menu -Menu $mainMenu  }

            { $_.StartsWith("set conf ") } { 

                $confFile = ($_ -split "set conf")[1].Trim()
                if (Set-Conf -ConfFile $confFile)
                {
                    $isConfFileSet = $true
                    Get-SysmonXmlData -confFile $confFile
                }
            }

            { $_.StartsWith("set state ") } { 
                
                if ($_.Split().Count -ne 3) { Write-ErrorMessage -Message "[-] Invalid number of arguments supported for command 'SET STATE'" }
                else { Set-State -StateSelected $_.Split()[2] }
            }

            { $_.StartsWith("set log ") } { 
                
                if ($_.Split().Count -ne 3) { Write-ErrorMessage -Message "[-] Invalid number of arguments supported for command 'SET LOG'" }
                else { Set-Log -LogOption $_.Split()[2] }
            }

            { $_ -eq "get eventlist" } { Get-EventList }

            { $_.StartsWith("set event ") } 
            { 
                if ((-not $state) -or (-not $isConfFileSet)) { Write-ErrorMessage -Message "[-] You need to set both config file & state before choosing events." }
                else
                {
                    if ($_.Split().Count -ne 3) { Write-ErrorMessage -Message "[-] Invalid number of arguments supported for command 'SET EVENT'" }
                    else {
                        $events = Set-Event -events $_.Split()[2]
                        if (-not $events) { $events = @() } 
                    }
                }
            }

            { $_ -eq "silent" } { Invoke-SilentSysmonPolicy -sysmonVersion $sysmonVersion }

            { $_ -eq "revert" } { Invoke-RevertSysmonPolicy }

            { $_ -eq "exit" } { exit }

            default { 
                if ($SysmonCommand -ne "exit") { Write-ErrorMessage -Message "Invalid command, type $($HELP_COMMANDS -join "/") for help"; $SysmonCommand = "" }
            }
        }
    }
}


function Get-SysmonXmlData
{
    param(
        [Parameter(Mandatory=$true)][string]$confFile
    )
    [xml]$xmlConfFile = Get-Content $confFile
    
    $RootPath = $xmlConfFile.Sysmon.EventFiltering
    $RuleGroups = $RootPath.RuleGroup
    $Global:ArchiveDirectory = $xmlConfFile.Sysmon.ArchiveDirectory
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
    # Find all RuleGroups
    foreach ($RuleGroup in $RuleGroups)
    {
        $EventNode = $RuleGroup.FirstChild
        $EventType = $EventNode.LocalName
        $OnMatch = $EventNode.Onmatch
        $EventID = $($EventDic[$EventType])
    
        ParseXmlData -OnMatch $OnMatch -EventNode $EventNode -EventID $EventID
    }
}


function Set-Conf
{
    param(
        [Parameter(Mandatory=$true)][string]$ConfFile
    )
    try { [xml]$xml = Get-Content $ConfFile -ErrorAction Stop }
    catch [System.Management.Automation.ArgumentTransformationMetadataException]{ 
        Write-ErrorMessage -Message "`n[-] Error while parsing xml file: $ConfFile"
        return 0
    }
    catch [System.Management.Automation.ItemNotFoundException]{ 
        Write-ErrorMessage -Message "`n[-] Error: Config file $ConfFile not found"
        return 0
    }
    catch {
        Write-ErrorMessage -Message "`n[-] Error: $_"
        return 0
    }

    Write-SuccessMessage -Message "[+] Sets config file to $ConfFile"
    return 1
}


function Set-State
{
    param(
        [Parameter(Mandatory=$true)][string]$StateSelected
    )
    switch ($StateSelected)
    {
        "online"
        {
            Write-SuccessMessage -Message "[+] State changed to ONLINE"
            $Global:state = $StateSelected
        }

        "offline"
        {
            Write-SuccessMessage -Message "[+] State changed to OFFLINE"
            $Global:state = $StateSelected
        }

        default { Write-ErrorMessage -Message "[-] Invalid state specified (should be online/offline)" }
    }
}


function Set-Log
{
    param(
        [Parameter(Mandatory=$true)][string]$LogOption
    )
    if ($LogOption -in @("on", "off"))
    {
        if ($LogOption -eq "on") { $logbool = $true }
        else { $logbool = $false }

        if ($logbool -ne $log) 
        { 
            $Global:log = $logbool
            if ($log) 
            {
                $path = Read-Host "Enter log path"
                Start-Transcript -Path $path
            }
            else { Stop-Transcript }
        }

        else { Write-ErrorMessage -Message "[-] Log is already $LogOption" }
    }

    else { Write-ErrorMessage -Message "[-] Invalid log option"; return 0 }
}


function Get-EventList
{
    @(1..$TOTAL_EVENTS) | 
    ForEach-Object { 
        foreach ($eid in $EventDic.Keys) 
        { 
            if ($EventDic[$eid] -eq $_) {
                Write-Host "SYSMONSTER Event Id No. $_ > " -ForegroundColor DarkRed -NoNewline
                Write-Host $eid -ForegroundColor Red
            }
        } 
    }
}


function Set-Event
{
    param(
        [Parameter(Mandatory=$true)]$events
    )
    [arraylist]$eventList = @()
    $isArrayValid = $true

    if ($events -match "^\d+$") { $eventList.Add([int]$events) }
    else 
    {
        switch ($events)
        {
            "all" { $eventList = @(1..$TOTAL_EVENTS) }

            { $_.Contains(",") } { $eventList = $_.Split(",") }

            { $_.Contains("-") } { $eventList = @(($_.Split("-")[0])..($_.Split("-")[1])) }

            default { Write-ErrorMessage -Message "[-] Invalid option of SET EVENT command"; return 0 }
        }
    }

    if ($eventList.Count -gt 1)
    {
        $eventList = foreach($eventNum in $eventList) {
            try {
                [int]::Parse($eventNum)
            }
            catch { Write-ErrorMessage -Message "[-] Invalid event value"; return 0 }
        }
    }

    $eventList | ForEach-Object { if (-not ($_ -in @(1..$TOTAL_EVENTS))) { Write-ErrorMessage -Message "[-] Event value out of range (1-$TOTAL_EVENTS)"; $isArrayValid = $false } }
    
    if (($eventList -contains 4) -or ($eventList -contains 16)) { Write-WarningMessage -Message "[!] Events 4 and 16 are not valid for sysmonster's checks" }
    @(4,16) | foreach-Object { $eventList.Remove($_) }
    if (-not $eventList.Count) { $isArrayValid = $false } 

    if (-not $isArrayValid) { Write-ErrorMessage -Message "[-] Invalid events"; return 0 }

    Write-SuccessMessage -Message "[+] Sets event/s to $events"
    Write-InfoMessage -Message "[*] Switching to event prompt"

    $doubleEids = @(13, 14, 18, 20, 21)
    $doubleEids |
    ForEach-Object {
        if (($_ -in $doubleEids) -and ($_ -in $eventList))
        {
            $eventList.Remove($_)
            if ($_ -in @(13, 14))
            {
                if (-not (12 -in $eventList)) { $eventList.Add(12) }
            }

            elseif ($_ -eq 18)
            {
                if (-not (17 -in $eventList)) { $eventList.Add(17) }
            }

            elseif ($_ -in @(20, 21))
            {
                if (-not (19 -in $eventList)) { $eventList.Add(19) }
            }
        }
    }

    if ($eventList.Count -gt 1) { $eventList = $eventList | Sort-Object }

    $eventList | 
    ForEach-Object {
        $eventId = $_
        $Sysmonster_tag += $eventId
        $SysmonCommand = ""
        $option = $null
        
        while ($SysmonCommand -ne "next")
        {
            $SysmonCommand = Read-SysmonCommand -Prompt $Sysmonster_tag

            switch ($SysmonCommand)
            {
                { $HELP_COMMANDS -contains $_ } { Show-Menu -Menu $secondaryMenu }

                { $_ -eq "show options" } { 
    
                    Show-Options -eid $eventId
                }

                { $_.StartsWith("set option ") } { 
    
                    if ($_.Split().Count -ne 3) { Write-ErrorMessage -Message "[-] Invalid number of arguments supported for command 'SET OPTION'" }
                    else 
                    { 
                        if (Set-Option -Option ([int]$_.Split()[2]) -eid $eventId) { $option = ([int]$_.Split()[2]) }
                    }
                }

                { $_ -eq "run" } { 
                    
                    if ($option) { Invoke-Run -Option $option -eid $eventId }
                    else { Write-ErrorMessage -Message "[-] No option selected" }
                }

                { $_ -eq "exit" } { exit }

                default { 

                    if ($SysmonCommand -ne "next") { 
                        Write-ErrorMessage -Message "Invalid command for this section, type $($HELP_COMMANDS -join "/") for help"
                    }
                    else { $Sysmonster_tag = $Sysmonster_tag[0..($Sysmonster_tag.Length-2)] }
                }
                }
        }
    }
    return 1
}


function Show-Options
{
    param(
        [Parameter(Mandatory=$true)][int]$eid
    )
    $optNum = 1

    foreach ($EventObj in $EventObjList)
    {
        $EventId = [int]$EventObj.eid
        
        if ($EventId -eq $eid)
        {
            $EventOptions = $EventObj.Options
            $EventName = Get-EventName -eid ([int]$eid)

            Write-Message -Message "[*] Note: an online option cannot run if offline mode was selected`n`n" -Color "Gray"
            Write-Message -Message "Options for event $EventName (eid $eid):`n" -Color "DarkRed"
            
            foreach ($opt in $EventOptions)
            {
                Write-Host "[$optNum] " -ForegroundColor DarkRed -NoNewline
                Write-Host "$($opt.Title) - $($opt.Description) " -ForegroundColor Cyan -NoNewline
                Write-Host "[STATE: $($opt.State)]" -ForegroundColor Magenta
                $optNum ++
            }
            break
        }
    }
}


function Get-EventName
{
    param(
        [Parameter(Mandatory=$true)][int]$eid
    )
    foreach ($eventName in $EventDic.Keys)
    {
        if ($EventDic[$eventName] -eq $eid)
        {
            return $eventName
        }
    }
}


function Set-Option
{
    param(
        [Parameter(Mandatory=$true)][int]$Option,
        [Parameter(Mandatory=$true)][int]$eid
    )
    $OptionObjectList = ($EventObjList.GetEnumerator() | Where-Object {$_.eid -eq $eid} | Select-Object Options).Options
    $EventOptionsNum = $OptionObjectList.Count
    $OptionObject = $OptionObjectList[$Option-1] 

    if (($Option -le $EventOptionsNum) -and ($Option -gt 0)) 
    { 
        if (($OptionObject.State -eq "online") -and ($state -eq "offline"))
        { 
            Write-ErrorMessage -Message "[-] Error: an online option cannot run with offline mode selected"
            return 0 
        }

        else
        {
            Write-SuccessMessage -Message "[+] Sets option to $Option"
            return 1
        }
    }
    else { Write-ErrorMessage -Message "[-] Invalid option"; return 0 }

    foreach ($EventObj in $EventObjList)
    {
        $EventId = $EventObj.eid
        
        if ($EventId -eq $eid)
        {
            $EventOptionsNum = $EventObj.Options.Count
            $EventOptionsNum
            
            if (($Option -le $EventOptionsNum) -and ($Option -gt 0)) 
            { 
                if (($state -eq "online") -or ($state -eq $EventObj.Options[$Option-1].State))
                {
                    Write-SuccessMessage -Message "[+] Sets option to $Option"
                    return 1
                }
            }
            else { Write-ErrorMessage -Message "[-] Invalid option"; return 0 }

            break
        }
    }
}


function Invoke-Run
{
    param(
        [Parameter(Mandatory=$true)][int]$Option,
        [Parameter(Mandatory=$true)][int]$eid
    )
    $ArchiveDirEvents = @("23", "24")
    $EventName = ($EventDic.GetEnumerator() | Where-Object { $_.Value -eq $eid } | Select-Object Name).Name
    $FunctionName = "Invoke-" + $EventName

    if ($state)
    {
        if (($OptionObject.State -eq "online") -and ($Option -eq "offline")) 
        { 
            Write-ErrorMessage -Message "[-] Error: an online option cannot run with offline mode selected" 
        }
        else
        {
            if ($eid -in $ArchiveDirEvents) 
            { 
                & $FunctionName -Option ([int]$Option) -ArchiveDirectory $ArchiveDirectory
            }
    
            else
            {
                & $FunctionName -Option ([int]$Option)
            }
        }
    }

    else { Write-ErrorMessage -Message "[-] Plz set a state (by set state command)" }
}


function Invoke-PermissionCheck
{
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$UserName,
        [Parameter(Mandatory=$true)]$Right,
        [Parameter(Mandatory=$true)][string]$permName
    )
    if (-not (Test-Path -Path $Path))
    {
        return "Path Not Found"
    }

    $allowedUsers = Get-Permissions -Path $Path -ReqPermission $Right
    if ($allowedUsers -icontains $UserName) 
    { 
        return $permName.ToUpper()+'ABLE'
    }
    else {
        if (-not $allowedUsers.Count) { return "NO" }
        else { return "accessed by: $($allowedUsers -join ', ')".Replace('accessed', "$permName-accessed") }
    }
}


function Write-Vector
{
    param(
        [Parameter(Mandatory=$true)][int]$eid
    )
    Write-Message -Message "Possible attack vectors for Event $eid :`n" -Color DarkMagenta
    foreach ($EventObj in $EventObjList)
    {
        $EventId = [int]$EventObj.eid
        
        if ($EventId -eq $eid)
        {
            $attackVector = $EventObj.attackVector
            Write-InfoMessage -Message $attackVector
            return
        }
    }
}


function Show-HighCheckTable
{
    param(
        [Parameter(Mandatory=$true)]$Table,
        [Parameter(Mandatory=$true)][int]$eid
    )
    $permissionFields = @('Image', 'CommandLine', 'ParentImage', 'ParentCommandLine', 'TargetFilename')
    $dirPattern = '^(?:[a-zA-Z]\:)?\\?(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$'
    $filePattern = '((?:[a-zA-Z]\:|\\\\[\(\)\d\w\s\.]+\\[\(\)\d\w\s\.$]+)\\(?:[\(\)\d\w\s\.]+\\)*[\d\w\s]*?\.\w{0,4})'
    $pathPattern = "($dirPattern|$filePattern)"
    $eidsPermissionsChecks = @(1, 2, 3, 5, 11, 12, 15, 22)
    
    $regConvert = @{
        "HKLM" = "HKLM:"
        "HKCR" = "HKCR:"
        "HKU" = "HKU:"
        "\REGISTRY\MACHINE" = "HKLM:"
        "\REGISTRY\MACHINE\SOFTWARE\Classes" = "HKCR:"
        "\REGISTRY\USER" = "HKU:"
    }

    # The permission mask contains 2 "bits" XXX
    # The 1st bit is for Write permission, 2nd for Execute
    $eidsPermissionsMask = @{
        1  = @(1, 1)
        2  = @(1, 0)
        3  = @(1, 1)
        11 = @(1, 0)
        12 = @(1, 1)
        15 = @(1, 0)
        22 = @(1, 1)
    }
    
    $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    if ([int]$eid -in $eidsPermissionsChecks)
    {
        $permissionMask = $eidsPermissionsMask[[int]$eid] 
        $writeCheck = $permissionMask[0]
        $executeCheck = $permissionMask[1]

        try
        {
            if ([int]$eid -eq 12) 
            {
                [void]$Table.Columns.Add("Attack Vector")
                [void]$Table.Columns.Add("Add Object")
                [void]$Table.Columns.Add("Set Value")
                [void]$Table.Columns.Add("Delete Object")
            }
            if ($writeCheck) { [void]$Table.Columns.Add("Writable") }
            if ($executeCheck) { [void]$Table.Columns.Add("Executable") }
        }
        catch {}

        $Table | ForEach-Object {
            
            $writeResult = @()
            $executeResult = @()

            if ($_.Field -in $permissionFields)
            {
                $checkString = ($_.Value).Replace('"','')
                $match = [regex]::Matches($checkString, $pathPattern)
                
                if ($match.Count)
                {
                    $match | ForEach-Object {
                        
                        $path = $_.Value
                        
                        if ($writeCheck)
                        {
                            $result = Invoke-PermissionCheck -Path $path -UserName $username -Right $Rights.WRITE -permName 'write'
                            if ($result) { $writeResult += $result }
                        }

                        if ($executeCheck)
                        {
                            $result = Invoke-PermissionCheck -Path $path -UserName $username -Right $Rights.EXECUTE -permName 'execute'
                            if ($result) { $executeResult += $result }
                        }
                    }
                }

                if ($writeResult) { $_.Writable = $writeResult -join ';' }
                if ($executeResult) { $_.Executable = $executeResult -join ';' }
            }

            if ($eid -eq 12)
            {
                if ($_.Field -eq "EventType") { $_.'Attack Vector' = "Entire Event Type is excluded (Attack Vector No.3)" }
                elseif ($_.Field -eq "TargetObject")
                {
                    if ($_.Condition -in @("end with", "contains")) { $_.'Attack Vector' = "Custom excluded registry path (Attack Vector No.1)" }
                    elseif ($_.Condition -eq "begin with")
                    {
                        # Replacing Registry value for powershell permission checks
                        $regObject = $_.Value.Trim()
                        $regPrefix = $regObject.Split("\")[0]
                        if ($regPrefix -in $regConvert.Keys)
                        {
                            $regObject = $regObject.Replace($regPrefix, $regConvert[$regPrefix])
                            $_.'Add Object' = (Get-Permissions -Path $regObject -ReqPermission $Rights.REG_CREATE -regCheck $true) -join ","
                            $_.'Set Value' = (Get-Permissions -Path $regObject -ReqPermission $Rights.REG_SET -regCheck $true) -join ","
                            $_.'Delete Object' = (Get-Permissions -Path $regObject -ReqPermission $Rights.REG_DELETE -regCheck $true) -join ","
                            if ($_.'Add Object' -or $_.'Set Value' -or $_.'Delete Object') { $_.'Attack Vector' = "Excluded operations on registry paths (Attack Vector No.2)" }
                        }
                    }
                }
            }
        }
    }

    return $Table
}


function Invoke-ExternalRuleHighCheck
{
    param(
        [Parameter(Mandatory=$true)][int]$eid,
        [Parameter(Mandatory=$true)][string]$Field,
        [Parameter(Mandatory=$true)]$Value
    )
    $permissionFields = @('Image', 'CommandLine', 'ParentImage', 'ParentCommandLine', 'TargetFilename')
    $dirPattern = '^(?:[a-zA-Z]\:)?\\?(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$'
    $filePattern = '((?:[a-zA-Z]\:|\\\\[\(\)\d\w\s\.]+\\[\(\)\d\w\s\.$]+)\\(?:[\(\)\d\w\s\.]+\\)*[\d\w\s]*?\.\w{0,4})'
    $pathPattern = "($dirPattern|$filePattern)"
    $eidsPermissionsChecks = @(1, 2, 3, 5, 11, 12, 15, 22)
    
    # The permission mask contains 2 "bits" XXX
    # The 1st bit is for Write permission, 2nd for Execute
    $eidsPermissionsMask = @{
        1  = @(1, 1)
        2  = @(1, 0)
        3  = @(1, 1)
        11 = @(1, 0)
        12 = @(1, 1)
        15 = @(1, 0)
        22 = @(1, 1)
    }
    
    $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    if ([int]$eid -in $eidsPermissionsChecks)
    {
        $permissionMask = $eidsPermissionsMask[[int]$eid] 
        $writeCheck = $permissionMask[0]
        $executeCheck = $permissionMask[1]

        $writeResult = @()
        $executeResult = @()

        if ($Field -in $permissionFields)
        {
            $checkString = ($Value).Replace('"','')
            $match = [regex]::Matches($checkString, $pathPattern)
            
            if ($match.Count)
            {
                $match | ForEach-Object {
                    
                    $path = $_.Value
                    
                    if ($writeCheck)
                    {
                        $result = Invoke-PermissionCheck -Path $path -UserName $username -Right $Rights.WRITE -permName 'write'
                        if ($result) { $writeResult += $result }
                    }

                    if ($executeCheck)
                    {
                        $result = Invoke-PermissionCheck -Path $path -UserName $username -Right $Rights.EXECUTE -permName 'execute'
                        if ($result) { $executeResult += $result }
                    }
                }
            }

            if ($writeResult) 
            { 
                $writeResult = $writeResult -join ';'
                $BgColor = ""

                if ($writeResult.Contains('WRITEABLE') -or $writeResult.Contains('write-accessed'))
                {
                    $BgColor = 'DarkRed'
                }

                Write-Message -Message "Writable: $writeResult" -Color ([System.Console]::ForegroundColor) -BgColor $BgColor
            }
            
            if ($executeResult) 
            { 
                $executeResult = $executeResult -join ';'
                Write-Message -Message "Executable: $writeResult" -Color ([System.Console]::ForegroundColor)
            }
        }
    }
}


function Show-Table
{
    param(
        [Parameter(Mandatory=$true)]$Table,
        [Parameter(Mandatory=$false)][bool]$highCheck,
        [Parameter(Mandatory=$false)][int]$eid
    )
    if ($highCheck) 
    {
        $Table = Show-HighCheckTable -Table $Table -eid $eid 
        $lines = ($Table | Format-Table -Wrap -AutoSize | Out-String) -replace "`r", "" -split "`n"

        foreach ($line in $lines)
        {
            $BgColor = ""

            if ($line.Contains('WRITEABLE') -or $line.Contains('write-accessed'))
            {
                $BgColor = 'DarkRed'
            }
        
            Write-Message -Message "$line" -Color ([System.Console]::ForegroundColor) -BgColor $BgColor
        }
    }
    
    else 
    { 
        try
        {
            [void]$Table.Columns.Remove("Writable")
            [void]$Table.Columns.Remove("Executable")
            [void]$Table.Columns.Remove("Add Object")
            [void]$Table.Columns.Remove("Set Value")
            [void]$Table.Columns.Remove("Delete Object")
            [void]$Table.Columns.Remove("Attack Vector")
        }
        catch {}

        Write-Host ($Table | Format-Table -Wrap -AutoSize | Out-String)
    }
}


function Read-SysmonCommand
{
    param(
        [Parameter(Mandatory=$true)]$Prompt
    )
    Write-Prompt $Prompt
    $Command = $Host.UI.ReadLine()
    
    return $Command.Trim().ToLower()
}


function Write-Prompt
{
    param(
        [Parameter(Mandatory=$true)]$Prompt
    )
    Write-Host
    foreach ($Prompt_Value in $Prompt)
    {
        Write-Host $Prompt_Value -NoNewline -ForegroundColor DarkCyan
        if ($Prompt.Count -ne 1 -and $Prompt_Value -ne $Prompt[-1]) 
        { 
            Write-Host $PROMPT_SEPERATOR -NoNewline -ForegroundColor DarkCyan 
        }
    }
    
    Write-Host "$PROMPT_ENDING " -NoNewline -ForegroundColor DarkCyan    
}


function Get-UserResponse
{
    param(
        [Parameter(Mandatory=$true)][string]$Message
    )
    $response = ""
    while ($response -notin @('y','n'))
    {
        $response = (Read-Host $Message).ToLower()  
    }
    return $response
}


function Write-IncludeMessage
{
    param(
        [Parameter(Mandatory=$true)][string]$Message
    )
    Write-Host $Message -ForegroundColor DarkRed
}


function Write-ExcludeMessage
{
    param(
        [Parameter(Mandatory=$true)][string]$Message
    )
    Write-Host $Message -ForegroundColor DarkGreen
}


function Write-ErrorMessage
{
    param(
        [Parameter(Mandatory=$true)][string]$Message
    )
    Write-Host $Message -ForegroundColor Red
}


function Write-SuccessMessage
{
    param(
        [Parameter(Mandatory=$true)][string]$Message
    )
    Write-Host $Message -ForegroundColor Green
}


function Write-InfoMessage
{
    param(
        [Parameter(Mandatory=$true)][string]$Message
    )
    Write-Host $Message -ForegroundColor Gray
}


function Write-WarningMessage
{
    param(
        [Parameter(Mandatory=$true)][string]$Message
    )
    Write-Host $Message -ForegroundColor DarkRed
}


function Write-Message
{
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Message,
        [Parameter(Mandatory=$true)]$Color,
        [Parameter(Mandatory=$false)]$BgColor
    )
    if ($BgColor) { Write-Host $Message -ForegroundColor $Color -BackgroundColor $BgColor }
    else { Write-Host $Message -ForegroundColor $Color }
}


function Write-EventDescription
{
    param(
        [Parameter(Mandatory=$true)][string]$Description
    )
    Write-Message -Message $Description -Color Cyan
}


function Invoke-DisplayEventRules
{
    <#
    .SYNOPSIS
        Universal helper for displaying include/exclude event rules with proper formatting.

    .DESCRIPTION
        Displays include and exclude rules for a specified Sysmon event, handling both
        internal rule tables and external rule definitions. Provides formatted output
        with color-coded messages and structured data presentation.

    .PARAMETER EventId
        The Sysmon Event ID to display rules for (e.g., 1 for ProcessCreate).

    .PARAMETER IncludeMessage
        Custom message to display before include rules section.

    .PARAMETER ExcludeMessage
        Custom message to display before exclude rules section.

    .OUTPUTS
        Formatted table output to console showing event rules and external rules.

    .NOTES
        - Called by Options 1 for all Sysmon event handlers
        - Uses global variables: $event_tables, $RuleDic, $INCLUDE_INDEX, $EXCLUDE_INDEX
    #>
    param(
        [Parameter(Mandatory=$true)][int]$EventId,
        [Parameter(Mandatory=$true)][string]$IncludeMessage,
        [Parameter(Mandatory=$true)][string]$ExcludeMessage
    )
    
    $include_table = $event_tables[$EventId-1][$INCLUDE_INDEX]
    $exclude_table = $event_tables[$EventId-1][$EXCLUDE_INDEX]
    
    # Display include rules
    if ($include_table.Rows.Count) {
        Write-IncludeMessage -Message "`n$IncludeMessage`n"
        Show-Table -Table $include_table
    }
    
    if ($RuleDic[$EventId].Count) { 
        ReportExternalRules -id $EventId -type "include" 
    }
    
    if ((-not $include_table.Rows.Count) -and (-not $RuleDic[$EventId].Count)) {
        Write-ErrorMessage -Message "`n[-] No included paths`n"
    }
    
    # Display exclude rules
    if ($exclude_table.Rows.Count) {
        Write-ExcludeMessage -Message "`n$ExcludeMessage`n"
        Show-Table -Table $exclude_table
    }
    
    if ($RuleDic[($EventId+$TOTAL_EVENTS)].Count) { 
        ReportExternalRules -id $EventId -type "exclude" 
    }
    
    if ((-not $exclude_table.Rows.Count) -and (-not $RuleDic[($EventId+$TOTAL_EVENTS)].Count)) {
        Write-ErrorMessage -Message "`n[-] No excluded paths`n"
    }
}


function Invoke-DisplayHighVectorRules
{
    <#
    .SYNOPSIS
        Universal helper for displaying attack vector analysis with permission checks.

    .DESCRIPTION
        Displays excluded rules with attack vector context and performs security analysis
        including file/registry permission validation. Identifies potential cases of attacker
        not being logged through improper exclusions.

    .PARAMETER EventId
        The Sysmon Event ID for vector analysis (e.g., 1 for ProcessCreate).

    .OUTPUTS
        Color-coded table with attack vector annotations and permission check results.

    .NOTES
        - Called by Options 2 for events supporting attack vector analysis
        - Highlights interesting paths where binaries could be swapped
    #>
    param(
        [Parameter(Mandatory=$true)][int]$EventId
    )
    
    $exclude_table = $event_tables[$EventId-1][$EXCLUDE_INDEX]
    
    Write-Vector -eid $EventId
    
    if ($exclude_table.Rows.Count) {
        Show-Table -Table $exclude_table -highCheck $true -eid $EventId
    }
    
    if ($RuleDic[($EventId+$TOTAL_EVENTS)].Count) {
        ReportExternalRules -id $EventId -type "exclude" -highCheck $true
    }
    
    if ((-not $exclude_table.Rows.Count) -and (-not $RuleDic[($EventId+$TOTAL_EVENTS)].Count)) {
        Write-ErrorMessage -Message "`n[-] No excluded paths`n"
    }
}


function Invoke-CheckFileWritePermissions 
{
    <#
    .SYNOPSIS
        Interactive helper for checking write permissions on files.

    .DESCRIPTION
        Prompts user for a file path and checks which users/groups have 'Write' permissions.
        Identifies if the current user has write access and reports all users with write privileges -
        but does not check group membership.
        Used to assess binary replacement risks in Sysmon excluded files.

    .OUTPUTS
        Console output listing users/groups with write permissions and current user status.

    .NOTES
        - Called by Options 3 for Events 1, 2, 3, 11, 15, 22
        - Critical for identifying file tampering risks
        - Requires file path to exist and be accessible
    #>
    $check_file = Read-Host "Enter file to check"
    
    if (Test-Path -Path $check_file) {
        $users = Get-Permissions -Path $check_file -ReqPermission $Rights.WRITE
        
        if ($users.Count) {
            $WhoamiUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Write-SuccessMessage -Message "`n[+] Users/Groups that have at least 'Write' permission:`n"
            
            foreach ($user in $users) {
                Write-SuccessMessage -Message $user
            }
            
            if ($users -icontains $WhoamiUser) { 
                Write-SuccessMessage -Message "`n[+] YOU ($WhoamiUser) have at least 'Write' Permission to file $check_file" 
            }
            else { 
                Write-ErrorMessage -Message "`n[-] YOU ($WhoamiUser) don't have at least 'Write' Permission to file $check_file"
                Write-InfoMessage -Message "[*] Check if you are in one of the accessed groups"
            }
        }
        else { 
            Write-ErrorMessage -Message "`n[-] No users have at least 'Write' permission`n" 
        }
    }
    else { 
        Write-ErrorMessage -Message "`n[-] Path does not exist`n" 
    }
}


function Invoke-CheckFileExecutePermissions
{
    <#
    .SYNOPSIS
        Interactive helper for checking execute permissions on files and threat assessment.

    .DESCRIPTION
        Prompts user for a file path and checks which users/groups have 'Execute' permissions.
        Identifies if the current user can execute the file (without checking group membership)
        and reports all users with execute privileges.
        Used to assess code execution risks in Sysmon excluded binaries.

    .OUTPUTS
        Console output listing users/groups with execute permissions and current user status.

    .NOTES
        - Called by Options 4 for Events 1, 3, 8, 10
        - Critical for identifying code execution risks
        - Evaluates ACLs to determine actual executable access
    #>
    $check_file = Read-Host "Enter file to check"
    
    if (Test-Path -Path $check_file) {
        $users = Get-Permissions -Path $check_file -ReqPermission $Rights.EXECUTE
        
        if ($users.Count) {
            $WhoamiUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Write-SuccessMessage -Message "`n[+] Users/Groups that have 'Execute' permission:`n"
            
            foreach ($user in $users) {
                Write-SuccessMessage -Message $user
            }
            
            if ($users -icontains $WhoamiUser) { 
                Write-SuccessMessage -Message "`n[+] YOU ($WhoamiUser) have 'Execute' Permission to file $check_file" 
            }
            else { 
                Write-ErrorMessage -Message "`n[-] YOU ($WhoamiUser) don't have 'Execute' Permission to file $check_file"
                Write-InfoMessage -Message "[*] Check if you are in one of the accessed groups"
            }
        }
        else { 
            Write-ErrorMessage -Message "`n[-] No users have 'Execute' permission`n" 
        }
    }
    else { 
        Write-ErrorMessage -Message "`n[-] Path does not exist`n" 
    }
}


Export-ModuleMember -Function Invoke-SysmonsterCLI, Initialize-SysmonVersionDatabase
Export-ModuleMember -Function Get-UserResponse,Write-IncludeMessage,Write-ExcludeMessage,Write-ErrorMessage
Export-ModuleMember -Function Write-SuccessMessage,Write-InfoMessage,Write-WarningMessage,Write-Message,Write-Vector
Export-ModuleMember -Function Write-EventDescription,Show-Table,Show-HighCheckTable,Invoke-PermissionCheck,Invoke-ExternalRuleHighCheck
Export-ModuleMember -Function Invoke-DisplayEventRules,Invoke-DisplayHighVectorRules,Invoke-CheckFileWritePermissions,Invoke-CheckFileExecutePermissions