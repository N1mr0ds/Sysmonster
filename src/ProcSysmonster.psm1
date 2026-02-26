$ProcessAccess = New-Object PSObject
$ProcessAccess | Add-Member -MemberType NoteProperty -Name "PROCESS_CREATE_THREAD" -Value 0x00000002
$ProcessAccess | Add-Member -MemberType NoteProperty -Name "PROCESS_QUERY_INFORMATION" -Value 0x00000400
$ProcessAccess | Add-Member -MemberType NoteProperty -Name "PROCESS_VM_OPERATION" -Value 0x00000008
$ProcessAccess | Add-Member -MemberType NoteProperty -Name "PROCESS_VM_WRITE" -Value 0x00000020
$ProcessAccess | Add-Member -MemberType NoteProperty -Name "PROCESS_VM_READ" -Value 0x00000010

function Invoke-ProcessCreate
{
    <#
    .SYNOPSIS
        Analyzes Sysmon Event 1 (ProcessCreate) exclusions and access control configuration.

    .DESCRIPTION
        Evaluates process creation event rules, identifies security risks from excluded processes,
        and checks file write/execute permissions on excluded binaries. Critical for detecting
        process tampering and binary replacement attack vectors.

    .PARAMETER Option
        Analysis mode: 1 = Rule parsing, 2 = High-risk analysis, 3 = Write permission check, 4 = Execute permission check

    .OUTPUTS
        Rule tables, attack vectors, and permission analysis based on selected option.

    .NOTES
        - Event ID: 1 (ProcessCreate)
        - Excluded Image/ParentImage with write permissions enables binary replacement
    #>
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["ProcessCreate"]
    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1) {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "`nThis table contains the processes you should avoid to launch:" `
            -ExcludeMessage "`nThis table contains the processes that will not be logged if launched:"
    }

    if ($Option -eq 2) {
        Invoke-DisplayHighVectorRules -EventId $id
    }

    if ($Option -eq 3) {
        Invoke-CheckFileWritePermissions
    }

    if ($Option -eq 4) {
        Invoke-CheckFileExecutePermissions
    }
}


function Invoke-ProcessTerminate
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["ProcessTerminate"]

    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1) {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "`nThis table contains the processes that will be logged if terminated:" `
            -ExcludeMessage "`nThis table contains the processes that will not be logged if terminated:"
    }
}


function Invoke-CreateRemoteThread
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["CreateRemoteThread"]
    
    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1) {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "`nThis table contains the processes that will be logged if used the Win32 API CreateRemoteThred call:" `
            -ExcludeMessage "`nThis table contains the processes that will not be logged if used the Win32 API CreateRemoteThred call:"
    }

    if ($Option -eq 2) {
        $exclude_table = $event_tables[$id-1][$EXCLUDE_INDEX]
        if ($exclude_table.Rows.Count) { 
            Invoke-CheckCreateRemoteThread -CheckTable $exclude_table 
        }
    }
}


function Invoke-CheckCreateRemoteThread
{
    param(
        [Parameter(Mandatory=$true)]$CheckTable
    )
    
    $id = $EventDic["CreateRemoteThread"]
    $ProcAc_Include = $event_tables[$id-1][$INCLUDE_INDEX]

    $accessed_procs = 0
    $openprocess = @"
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
"@
    $kernel32 = Add-Type -MemberDefinition $openprocess -Name "OpenProc" -Namespace Win32Functions -PassThru

    Write-InfoMessage -Message "[*] For creating a remote thread, a handle of proccess must have the`nPROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, and PROCESS_VM_WRITE access rights"
    Write-SuccessMessage -Message "`n[+] Checking access rigths for processes on exclude rules`n"

    foreach ($Row in $CheckTable.Rows)
    {
        if ($Row.Field -eq "TargetImage")
        {
            $procPath = $Row.Value
            $check = 'y'

            if ($ProcAc_Include.Rows.Count) 
            {
                foreach ($ProcAc_Row in $ProcAc_Include.Rows)
                {
                    if ($ProcAc_Row.Value -eq $procPath)
                    {
                        Write-WarningMessage -Message "[!] Executing OpenProcess function with $procPath will be monitored by Event No. 10 (ProcessAccess)"
                        $check = Get-UserResponse -Message "Are you sure you want to check this path? (y/n)"
                        break
                    }
                }
            }

            if ($check -eq 'y')
            {
                $pid_list = Get-Process | Where-Object {$null -ne $_.Path} | Where-Object {$_.Path -eq $procPath} | ForEach-Object {$_.Id}
            
                if ($null -eq $pid_list) { 
                    Write-ErrorMessage -Message "[-] Path $procPath not found in current running processes paths" 
                }
            
                else
                {
                    foreach ($ProcID in $pid_list)
                    {
                        $proc_access = @($ProcessAccess.PROCESS_CREATE_THREAD, 
                                         $ProcessAccess.PROCESS_QUERY_INFORMATION,
                                         $ProcessAccess.PROCESS_VM_OPERATION,
                                         $ProcessAccess.PROCESS_VM_READ,
                                         $ProcessAccess.PROCESS_VM_WRITE)
                
                        $isAccessed = $true
                        foreach($access in $proc_access)
                        {
                            $handle = $kernel32::OpenProcess($access, $false, $ProcID)
                            if ($handle) { $kernel32::CloseHandle($handle) | Out-Null } 
                            else { $isAccessed = $false }
                        }

                        if ($isAccessed) 
                        { 
                            Write-SuccessMessage -Message "[+] Can create remote thread: process pid No. $ProcID ($procPath)"
                            $accessed_procs ++
                        }
                        else { 
                            Write-ErrorMessage -Message "[-] Cannot create remote thread: process pid No. $ProcID ($procPath) has no access for remote thread" 
                        }
                    }
                }
            }
        }
    }

    if (-not $accessed_procs) { 
        Write-ErrorMessage -Message "[-] Cannot create remote thread for all processes"  
    }
}


function Invoke-ProcessAccess
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["ProcessAccess"]
    
    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1) {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "`nThis table contains the processes that will be logged if tried to open another local process by OpenProcess function:" `
            -ExcludeMessage "`nThis table contains the processes that will not be logged if tried to open another local process by OpenProcess function:"
    }
}


function Invoke-ProcessTampering
{
    param(
        [Parameter(Mandatory=$true)][int]$Option
    )
    
    $id = $EventDic["ProcessTampering"]
    
    Write-EventDescription -Description $InfoDic[$id]

    if ($Option -eq 1) {
        Invoke-DisplayEventRules -EventId $id `
            -IncludeMessage "`nThis table contains the processes that will be logged when their image is changed from an external source, such as a different process:" `
            -ExcludeMessage "`nThis table contains the processes that will not be logged when their image is changed from an external source, such as a different process:"
    }
}

Export-ModuleMember -Function Invoke-ProcessCreate,Invoke-ProcessTerminate,Invoke-CreateRemoteThread,Invoke-CheckCreateRemoteThread
Export-ModuleMember -Function Invoke-ProcessAccess,Invoke-ProcessTampering
