
<#PSScriptInfo
 
.VERSION 1.5.1
 
.GUID 4212e294-a195-4cbd-8e61-9c33268b7791
 
.AUTHOR saw-friendship
 
.COMPANYNAME
 
.COPYRIGHT
 
.TAGS netstat
 
.LICENSEURI
 
.PROJECTURI
 
.ICONURI
 
.EXTERNALMODULEDEPENDENCIES
 
.REQUIREDSCRIPTS
 
.EXTERNALSCRIPTDEPENDENCIES
 
.RELEASENOTES
 
 
.PRIVATEDATA
 
#>

<#
 
.DESCRIPTION
 netstat for Windows7/2008R2 like Get-NetTCPConnection with IncludeProcessInfo feature
 
#> 

param (
    [string]$LocalAddress = '*',
    [string]$LocalPort = '*',
    [string]$RemoteAddress = '*',
    [string]$RemotePort = '*',
    [ValidateSet('Closed','Listen','SynSent','SynReceived','Established','FinWait1','FinWait2','CloseWait','Closing','LastAck','TimeWait','DeleteTCB','Bound')][string[]]$State = @('*'),
    [ValidateSet('TCP','UDP','TCPv6','UDPv6')][string[]]$Protocol = @('TCP'),
    [string]$OwningProcess = '*',
    [switch]$IncludeProcessInfo
)

if ($State -eq @('*')) {
    $State = @('Closed','Listen','SynSent','SynReceived','Established','FinWait1','FinWait2','CloseWait','Closing','LastAck','TimeWait','DeleteTCB','Bound')
}

$OSNotLegacy = [System.Version](Get-WmiObject -Class Win32_OperatingSystem).Version -ge [System.Version]('6.2')
$PSNotLegacy = [System.Version]$PSVersionTable.PSVersion -ge [System.Version]('5.1')

$NetstatParam = '-ano'
if ($PSNotLegacy -and $OSNotLegacy -and $State -contains 'Bound') {$NetstatParam += 'q'}


$SelectPropertyNetstat = @(
    @{Name = 'Protocol'; Expression = {$_.LineArr[0]}},
    @{Name = 'LocalAddress'; Expression = {$_.LineArr[1] -replace @($regex,'$1')}},
    @{Name = 'LocalPort'; Expression = {[UInt32]($_.LineArr[1] -replace @($regex,'$2'))}},
    @{Name = 'RemoteAddress'; Expression = {$_.LineArr[2] -replace @($regex,'$1')}},
    @{Name = 'RemotePort'; Expression = {[UInt32]($_.LineArr[2] -replace @($regex,'$2'))}},
    @{Name = 'State'; Expression = {$StateTable[$_.LineArr[3]]}},
    @{Name = 'OwningProcess'; Expression = {[UInt32]$_.LineArr[4]}}    
)

$SelectPropertyProcess = @('*')

if ($IncludeProcessInfo) {

    if ($PSNotLegacy) {
        $ProcessInfo = Get-Process -IncludeUserName | Select-Object -Property @(
            'ProcessName',
            @{Name = 'ProcessId'; Expression = {$_.id}},
            'UserName',
            'Path'
        ) | Group-Object -Property ProcessId -AsHashTable -AsString
    } else {
        $ProcessInfo = Get-WmiObject -Class Win32_Process | Select-Object -Property @(
            'ProcessName',
            'ProcessId',
            @{Name = 'UserName'; Expression = {$GetOwner = $_.GetOwner(); @{$true = (@($GetOwner.Domain,$GetOwner.User) -join '\')}[$GetOwner.ReturnValue -eq 0]}},
            'Path'
        ) | Group-Object -Property ProcessId -AsHashTable -AsString
    }
    
    $SelectPropertyProcess += @{Name = 'ProcessName'; Expression = {$ProcessInfo[[string]($_.OwningProcess)].ProcessName}}
    $SelectPropertyProcess += @{Name = 'UserName'; Expression = {$ProcessInfo[[string]($_.OwningProcess)].UserName}}
    $SelectPropertyProcess += @{Name = 'Path'; Expression = {$ProcessInfo[[string]($_.OwningProcess)].Path}}
    
}

$StateTable = @{
    'LISTEN' = 'Listen'
    'LISTENING' = 'Listen'
    'SYN_SENT' = 'SynSent'
    'SYN_RECEIVED' = 'SynReceived'
    'ESTABLISHED' = 'Established'
    'CLOSE_WAIT' = 'CloseWait'
    'FIN_WAIT_1' = 'FinWait1'
    'CLOSING' = 'Closing'
    'LAST_ACK' = 'LastAck'
    'CLOSED' = 'Closed'
    'FIN_WAIT_2' = 'FinWait2'
    'TIME_WAIT' = 'TimeWait'
    'Bound' = 'Bound'
    'DeleteTCB' = 'DeleteTCB'
}

$regex = '\[?([\.\d\:\%a-z\*]+)\]?\:([\d\*]+)$'

$Protocol | % {(netstat.exe $NetstatParam -p $_) -split '\n' |
        Select-String -Pattern '(\s+[\S]+){4,5}' |
        Select-Object -Skip 1 -Property @{Name = 'LineArr'; Expression = {$_ -split '\s\s+' -match '\S'}}
    } |
    Select-Object -Property $SelectPropertyNetstat |
    Select-Object -Property $SelectPropertyProcess | ? {
        ($_.LocalAddress -like $LocalAddress) -and
        ($_.LocalPort -like $LocalPort -or !$_.LocalPort) -and
        ($_.RemoteAddress -like $RemoteAddress) -and
        ($_.RemotePort -like $RemotePort) -and
        ($State -contains $_.State) -and
        ($_.OwningProcess -like $OwningProcess)
    }