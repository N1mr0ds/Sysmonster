function Invoke-FileCreateTime
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["FileCreateTime"]

    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the paths of files you should avoid to use to change their timestamps:" `
            -ExcludeMessage "This table contains the paths of files you should use to change their timestamps:"
    }

    if ($Option -eq 2)
    {
        Invoke-DisplayHighVectorRules -EventId $id
    }
        
    if ($Option -eq 3)
    {
        Invoke-CheckFileWritePermissions
    }
}


function Invoke-FileCreate
{
    <#
    .SYNOPSIS
        Analyzes Sysmon Event 11 (FileCreate) exclusions and file vectors.

    .DESCRIPTION
        Evaluates file creation event rules to identify exclusions that could exclude file-based logs. 
        Checks write permissions on excluded paths to identify risks.

    .PARAMETER Option
        Analysis mode: 1 = Rule parsing, 2 = High-risk analysis, 3 = Write permission check

    .OUTPUTS
        Rule tables, attack vectors, and permission analysis based on selected option.

    .NOTES
        - Event ID: 11 (FileCreate)
        - Excluded directories with write permissions permits unlogged persistent file placement
    #>
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["FileCreate"]

    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the paths of files you should avoid to use to create/change their content:" `
            -ExcludeMessage "This table contains the paths of files you should use to create/change their content:"
    }

    if ($Option -eq 2)
    {
        Invoke-DisplayHighVectorRules -EventId $id
    }
        
    if ($Option -eq 3)
    {
        Invoke-CheckFileWritePermissions
    }
}


function Invoke-FileCreateStreamHash
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["FileCreateStreamHash"]

    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the paths of files you should avoid to use to create Alternate Data Streams (ADS):" `
            -ExcludeMessage "This table contains the paths of files you should use to create Alternate Data Streams (ADS):"
    }

    if ($Option -eq 2)
    {
        Invoke-DisplayHighVectorRules -EventId $id
    }
  
    if ($Option -eq 3)
    {
        Invoke-CheckFileWritePermissions
    }
}


function Invoke-FileDelete
{
    param(
        [Parameter(Mandatory=$true)][int]$Option,
        [Parameter(Mandatory=$false)][string]$ArchiveDirectory
    )
    
    $id = $EventDic["FileDelete"]

    Write-EventDescription -Description $InfoDic[$id]
    
    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the files that will be logged (and maybe will be archived) if deleted:" `
            -ExcludeMessage "This table contains the files that will not be logged (and will not be archived) if deleted:"
    }
        
    if ($Option -eq 3)
    {
        $check_file = Read-Host "Enter file to check"
            
        if (Test-Path -Path $check_file)
        {
            $users = Get-Permissions -Path $check_file -ReqPermission $Rights.DELETE
            
            if ($users.Count)
            {
                $WhoamiUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                Write-SuccessMessage -Message "`n[+] Users/Groups that have at least 'Delete' permission:`n"
                foreach ($user in $users)
                {
                    Write-SuccessMessage -Message $user
                }

                if ($users -icontains $WhoamiUser) { Write-SuccessMessage -Message "`n[+] YOU ($WhoamiUser) have at least 'Delete' Permission to file $check_file" }
                else { 
                    Write-ErrorMessage -Message "`n[-] YOU ($WhoamiUser) don't have at least 'Delete' Permission to file $check_file"
                    Write-InfoMessage -Message "[*] Check if you are in one of the accessed groups"
                }
            }
            else { Write-ErrorMessage -Message "`n[-] No users have at least 'Delete' permission`n" }
        }
        else { Write-ErrorMessage -Message "`n[-] Path does not exist`n" }
    }

    if ($Option -eq 4) 
    {
        if ($ArchiveDirectory)
        {
            Write-WarningMessage -Message "`n[!] Found Archive Directory at conf file: $ArchiveDirectory"
            Write-WarningMessage -Message "[!] All included files will be archived to this directory`n"
        
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


function Invoke-FileDeleteDetected
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["FileDeleteDetected"]

    Write-EventDescription -Description $InfoDic[$id]
    
    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the files that will be logged if deleted (in case they won't be archive):" `
            -ExcludeMessage "This table contains the files that will not be logged if deleted (in case they won't be archive):"
    }
  
    if ($Option -eq 2)
    {
        $check_file = Read-Host "Enter file to check"
            
        if (Test-Path -Path $check_file)
        {
            $users = Get-Permissions -Path $check_file -ReqPermission $Rights.DELETE
            
            if ($users.Count)
            {
                $WhoamiUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                Write-SuccessMessage -Message "`n[+] Users/Groups that have at least 'Delete' permission:`n"
                foreach ($user in $users)
                {
                    Write-SuccessMessage -Message $user
                }

                if ($users -icontains $WhoamiUser) { Write-SuccessMessage -Message "`n[+] YOU ($WhoamiUser) have at least 'Delete' Permission to file $check_file" }
                else { 
                    Write-ErrorMessage -Message "`n[-] YOU ($WhoamiUser) don't have at least 'Delete' Permission to file $check_file"
                    Write-InfoMessage -Message "[*] Check if you are in one of the accessed groups"
                }
            }

            else { Write-ErrorMessage -Message "`n[-] No users have at least 'Delete' permission`n" }
        }

        else { Write-ErrorMessage -Message "`n[-] Path does not exist`n" }
    }
}


function Invoke-FileBlockExecutable
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["FileBlockExecutable"]

    Write-EventDescription -Description $InfoDic[$id]
    
    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the files that will be blocked if created:" `
            -ExcludeMessage "This table contains the files that will not be blocked if created:"
    }
}


function Invoke-FileBlockShredding
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["FileBlockShredding"]

    Write-EventDescription -Description $InfoDic[$id]
    
    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the files that will be blocked if tried deleted by file shredding technique:" `
            -ExcludeMessage "This table contains the files that will not be blocked if tried deleted by file shredding technique:"
    }
}


function Invoke-FileExecutableDetected
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["FileExecutableDetected"]

    Write-EventDescription -Description $InfoDic[$id]
    
    if ($Option -eq 1)
    {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "This table contains the executable files (PE format) that will be logged if created:" `
            -ExcludeMessage "This table contains the executable files (PE format) that will not be logged if created:"
    }
}


Export-ModuleMember -Function Invoke-FileCreateTime,Invoke-FileCreate,Invoke-FileCreateStreamHash
Export-ModuleMember -Function Invoke-FileDelete,Invoke-FileDeleteDetected,Invoke-FileBlockExecutable,Invoke-FileBlockShredding,Invoke-FileExecutableDetected
