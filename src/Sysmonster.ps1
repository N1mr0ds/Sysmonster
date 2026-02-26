using namespace System.Collections

$TOTAL_EVENTS = 29
$INCLUDE_INDEX = 0
$EXCLUDE_INDEX = 1

$RuleDic = New-Object 'System.Collections.Generic.Dictionary[int, arraylist]'
$EventDic = New-Object 'System.Collections.Generic.Dictionary[string, int]'
$InfoDic = New-Object 'System.Collections.Generic.Dictionary[int, string]'

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

$InfoDic = @{
    1  = "`nSYSMON EVENT ID 1 : PROCESS CREATION [ProcessCreate]`n";
    2  = "`nSYSMON EVENT ID 2 : FILE CREATION TIME RETROACTIVELY CHANGED IN THE FILESYSTEM [FileCreateTime]`n";
    3  =  "`nSYSMON EVENT ID 3 : NETWORK CONNECTION INITIATED [NetworkConnect]`n";
    5  = "`nSYSMON EVENT ID 5 : PROCESS ENDED [ProcessTerminate]`n";
    6  = "`nSYSMON EVENT ID 6 : DRIVER LOADED INTO KERNEL [DriverLoad]`n";
    7  = "`nSYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS [ImageLoad]`n";
    8  = "`nSYSMON EVENT ID 8 : REMOTE THREAD CREATED [CreateRemoteThread]`n";
    9  = "`nSYSMON EVENT ID 9 : RAW DISK ACCESS [RawAccessRead]`n";
    10 = "`nSYSMON EVENT ID 10 : INTER-PROCESS ACCESS [ProcessAccess]`n";
    11 = "`nSYSMON EVENT ID 11 : FILE CREATED [FileCreate]`n";
    12 = @"
         `nSYSMON EVENT ID 12 & 13 & 14 : REGISTRY MODIFICATION [RegistryEvent]
         EVENT 12: Registry object added or deleted
         EVENT 13: Registry value set
         EVENT 14: Registry objected renamed`n 
"@;
    15 = "`nSYSMON EVENT ID 15 : ALTERNATE DATA STREAM CREATED [FileCreateStreamHash]`n";
    17 = @"
        `nSYSMON EVENT ID 17 & 18 : PIPE CREATED / PIPE CONNECTED [PipeEvent]
         EVENT 17: Pipe Created
         EVENT 18: Pipe Connected`n
"@;
    19 = "`nSYSMON EVENT ID 19 & 20 & 21 : WMI EVENT MONITORING [WmiEvent]`n";
    22 = "`nSYSMON EVENT ID 22 : DNS QUERY [DnsQuery]`n";
    23 = "`nSYSMON EVENT ID 23 : FILE DELETE [FileDelete]`n";
    24 = "`nSYSMON EVENT ID 24 : CLIPBOARD EVENT MONITORING [ClipboardChange]`n";
    25 = "`nSYSMON EVENT ID 25 : PROCESS TAMPERING [ProcessTampering]`n";
    26 = "`nSYSMON EVENT ID 26 : FILE DELETE DETECTED [FileDeleteDetected]`n";
    27 = "`nSYSMON EVENT ID 27 : FILE BLOCK EXECUTABLE [FileBlockExecutable]`n";
    28 = "`nSYSMON EVENT ID 28 : FILE BLOCK SHREDDING [FileBlockShredding]`n";
    29 = "`nSYSMON EVENT ID 29 : FILE EXECUTABLE DETECTED [FileExecutableDetected]`n";
};

[arraylist]$event_tables = @()

$Rights = New-Object PSObject
$Rights | Add-Member -MemberType NoteProperty -Name "WRITE" -Value @('FullControl', 'TakeOwnersip', 'ChangePermissions', 'Write', 'WriteData', 'Modify', 'Modify, Synchronize')
$Rights | Add-Member -MemberType NoteProperty -Name "EXECUTE" -Value @('FullControl', 'TakeOwnersip', 'ChangePermissions', 'ReadAndExecute', 'ReadAndExecute, Synchronize', 'ExecuteFile')
$Rights | Add-Member -MemberType NoteProperty -Name "DELETE" -Value @('FullControl', 'TakeOwnersip', 'ChangePermissions', 'Delete')
$Rights | Add-Member -MemberType NoteProperty -Name "REG_CREATE" -Value @('FullControl', 'TakeOwnership', 'ChangePermissions', 'WriteKey', 'CreateSubKey')
$Rights | Add-Member -MemberType NoteProperty -Name "REG_DELETE" -Value @('FullControl', 'TakeOwnership', 'ChangePermissions', 'WriteKey', 'Delete')
$Rights | Add-Member -MemberType NoteProperty -Name "REG_SET" -Value @('FullControl', 'TakeOwnership', 'ChangePermissions', 'WriteKey', 'SetValue')
$Rights | Add-Member -MemberType NoteProperty -Name "REG_RENAME" -Value @('FullControl', 'TakeOwnership', 'ChangePermissions', 'WriteKey')

$regDrivers = @{
    "HKLM" = "HKEY_LOCAL_MACHINE"
    "HKCU" = "HKEY_CURRENT_USER"
    "HKCR" = "HKEY_CLASSES_ROOT"
    "HKU" = "HKEY_USERS"
    "HKCC" = "HKEY_CURRENT_CONFIG"
}

function Write-Banner
{
    Write-Host `n`n
    Write-Host '  ██████▓██   ██▓  ██████  ███▄ ▄███▓ ▒█████   ███▄    █   ██████ ▄▄▄█████▓▓█████  ██▀███  ' -ForegroundColor Gray ; 
    Write-Host '▒██    ▒ ▒██  ██▒▒██    ▒ ▓██▒▀█▀ ██▒▒██▒  ██▒ ██ ▀█   █ ▒██    ▒ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒' -ForegroundColor Gray ; 
    Write-Host '░ ▓██▄    ▒██ ██░░ ▓██▄   ▓██    ▓██░▒██░  ██▒▓██  ▀█ ██▒░ ▓██▄   ▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒' -ForegroundColor Gray ; 
    Write-Host '  ▒   ██▒ ░ ▐██▓░  ▒   ██▒▒██    ▒██ ▒██   ██░▓██▒  ▐▌██▒  ▒   ██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  ' -ForegroundColor Gray ; 
    Write-Host '▒██████▒▒ ░ ██▒▓░▒██████▒▒▒██▒   ░██▒░ ████▓▒░▒██░   ▓██░▒██████▒▒  ▒██▒ ░ ░▒████▒░██▓ ▒██▒' -ForegroundColor Gray ; Sleep -MilliSeconds 700
    Write-Host '▒ ▒▓▒ ▒ ░  ██▒▒▒ ▒ ▒▓▒ ▒ ░░ ▒░   ░  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░' -ForegroundColor Gray ; Sleep -MilliSeconds 700
    Write-Host '░ ░▒  ░ ░▓██ ░▒░ ░ ░▒  ░ ░░  ░      ░  ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░▒  ░ ░    ░     ░ ░  ░  ░▒ ░ ▒░' -ForegroundColor Gray ; Sleep -MilliSeconds 700
    Write-Host '░  ░  ░  ▒ ▒ ░░  ░  ░  ░  ░      ░   ░ ░ ░ ▒     ░   ░ ░ ░  ░  ░    ░         ░     ░░   ░ ' -ForegroundColor Gray ; Sleep -MilliSeconds 700
    Write-Host '      ░  ░ ░           ░         ░       ░ ░           ░       ░              ░  ░   ░     ' -ForegroundColor Gray ; Sleep -MilliSeconds 700
    Write-Host '         ░ ░                                                                               ' -ForegroundColor Gray ; Sleep -MilliSeconds 700
    Write-Host '                                                                                           ' -ForegroundColor Gray ; Sleep -MilliSeconds 700
}


function ReturnTable
{
    $table = New-Object System.Data.DataTable
    [void]$table.Columns.Add("Field")
    [void]$table.Columns.Add("Condition")
    [void]$table.Columns.Add("Value")
    [void]$table.Columns.Add("Name")
    return ,$table
}

@(1..$TOTAL_EVENTS) | ForEach-Object { [void]$event_tables.Add(@((ReturnTable), (ReturnTable))) }

@(1..($TOTAL_EVENTS*2)) | ForEach-Object { $RuleDic.Add($_, [arraylist]@()) }


function CreateTable
{
    param(
        [Parameter(Mandatory=$true)]$EventNode,
        [Parameter(Mandatory=$true)]$Table,
        [Parameter(Mandatory=$true)][int]$EventID,
        [Parameter(Mandatory=$true)][string]$Type
    )
    if ($EventNode.ChildNodes.Count -ne 0)
    {
        foreach ($ChildNode in $EventNode.ChildNodes)
        {
            $localname = $ChildNode.localname

            if ($localname -eq '#comment') { continue }

            if ($ChildNode.localname -eq "Rule") 
            {
                if ($Type -eq "include") { $id = $EventID }
                else { $id = $EventID + $TOTAL_EVENTS }

                $RuleElements = $ChildNode.ChildNodes
                $GroupRelation = $ChildNode.groupRelation
                [void]$RuleDic[$id].Add($GroupRelation)

                foreach ($RuleElement in $RuleElements )
                {
                    $condition = $RuleElement.condition
                    $value = $RuleElement.'#text'
                    $name = $RuleElement.localname
                    [void]$RuleDic[$id].Add([System.Tuple]::Create($name, $condition, $value))
                }
            }

            else 
            {
                $condition = $ChildNode.condition
                $value = $ChildNode.'#text'
                $name = $ChildNode.name
            
                [void]$Table.Rows.Add($localname, $condition, $value, $name)
            }  
                  
        }
        return 1
    }
    return 0
}


function ParseXmlData
{
    param(
        [Parameter(Mandatory=$true)][string]$OnMatch,
        [Parameter(Mandatory=$true)]$EventNode,
        [Parameter(Mandatory=$true)][int]$EventID
    )
    switch -Exact ($OnMatch) {
        "include"
        {
            $include_table = $event_tables[$EventID-1][$INCLUDE_INDEX]
            $created = CreateTable -EventNode $EventNode -Table $include_table -EventID $EventID -Type $OnMatch
            if (-not $created) { $include_table = $null }
        }

        "exclude"
        {
            $exclude_table = $event_tables[$EventID-1][$EXCLUDE_INDEX]
            $created = CreateTable -EventNode $EventNode -Table $exclude_table -EventID $EventID -Type $OnMatch
            if (-not $created) { $exclude_table = $null }
        }
    }
}


function ReportExternalRules
{
    param(
        [Parameter(Mandatory=$true)][int]$id,
        [Parameter(Mandatory=$true)][string]$type,
        [Parameter(Mandatory=$false)][bool]$highCheck
    )
    $ruleNum = 0
    $elementNum = 0

    if ($type -eq "exclude") { $id += $TOTAL_EVENTS }

    foreach ($RuleNode in $RuleDic[$id])
    {
        
        if ($RuleNode.GetType().Name -eq "String")
        {
            $elementNum = 0
            $groupRelation = $RuleNode.ToUpper()
            $ruleNum ++
            "-"*25
            Write-Message -Message "External rule No. $ruleNum (type: $type):`n" -Color "DarkRed"
        }

        # Rule Tuple
        else
        {
            $field = $RuleNode.Item(0)
            $condition = $RuleNode.Item(1)
            $value = $RuleNode.Item(2)
            if ($elementNum -ne 0) { Write-Message -Message "`n`t $groupRelation`n" -Color "Red" }
            $elementNum ++
            Write-Message -Message "Field: $field`nCondition: $condition`nValue: $value`n" -Color ([System.Console]::ForegroundColor)
            if ($highCheck) { Invoke-ExternalRuleHighCheck -eid ($id-$TOTAL_EVENTS) -Field $field -Value $value }
        }
    }
    "-"*25
}


function Get-Permissions
{
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)]$ReqPermission,
        [Parameter(Mandatory=$false)][bool]$Display,
        [Parameter(Mandatory=$false)][bool]$regCheck
    )
    try { $acllist = (Get-Acl -path $Path -ErrorAction Stop).Access }
    catch [System.Management.Automation.DriveNotFoundException]
    {
        $regDriveName = $Error[0].TargetObject
        $regProviderRoot = $regDrivers[$regDriveName]
        New-PSDrive -PSProvider Registry -Root $regProviderRoot -Name $regDriveName | Out-Null
    }
    catch {}

    $permDic = @{}
    $notInterested = @('NT SERVICE\TrustedInstaller', 'APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES', 'APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES')

    foreach ($acl in $acllist)
    {
        if ($acl.AccessControlType -eq "Allow")
        {
            $userGroup = $acl.IdentityReference.ToString().Trim()
            if ($regCheck) { $permission = $acl.RegistryRights.ToString().Trim() }
            else { $permission = $acl.FileSystemRights.ToString().Trim() }

            if (-not ($userGroup -in $notInterested)) 
            {
                if ($permission -notmatch "\d+")
                {
                    if (-not ($permission -in $permDic[$userGroup])) 
                    { 
                        $permDic[$userGroup] += @($permission) 
                    }
                }
            }
        }
    }

    if ($Display) { return $permDic }

    # Return only the relevant users/groups
    $userGroupList = @()
    foreach ($permKey in $permDic.Keys)
    {
        $permissions = $permDic[$permKey]
        foreach ($allowPerm in $permissions)
        {
            if ($allowPerm -in $ReqPermission)
            {
                $userGroupList += @($permKey)
            }
        }
    }

    return $userGroupList
}

function Get-PermissionString
{
    param(
        [Parameter(Mandatory=$true)][string]$Path
    )
    $permDic = Get-Permissions -Path $Path -Display $true
    $permissions = ""

    foreach ($permKey in $permDic.keys) 
    {
        $permissions += "`n$permKey : $($permDic[$permKey] -join ', ')"
    }
    
    return $permissions
}


function Import-SysmonsterModule
{
    $SysmonsterModules = @("\ProcSysmonster.psm1", "\FileSysmonster.psm1", "\OtherSysmonster.psm1", "\SysmonsterHelper.psm1")

    foreach ($module in $SysmonsterModules)
    {
        try { Import-Module -Name ($PSScriptRoot+$module) }
        catch { 
            Write-WarningMessage -Message "`n[!] Error while importing module $module :`n$_"
            exit
        }
    }

}


function Invoke-Sysmonster
{
    # Changing the window width to 500 for dealing with Sysmonster tables
    # Note: if the window is moving, the width will set to default
    $widthSize = $Host.UI.RawUI.BufferSize.Width
    if ($widthSize -lt 500) { $Host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(500, $Host.UI.RawUI.BufferSize.Height) }
    
    Import-SysmonsterModule
    Write-Banner
    # Initialize Sysmonster's version database
    Initialize-SysmonVersionDatabase | Out-Null
    Invoke-SysmonsterCLI
}

Invoke-Sysmonster