$today = Get-Date
$weekAgo = $today.AddDays(-7)
$username = $env:USERNAME
$logName = "Security"

$events = Get-WinEvent -FilterHashtable @{LogName=$logName;StartTime=$weekAgo;EndTime=$today;ID=4624,4634;Level=0} -ErrorAction SilentlyContinue |
Where-Object {$_.Properties[5].Value -eq $username}

if ($events) {
    $events | Format-Table TimeCreated, Id, Message -AutoSize | Out-File -FilePath "C:\log.txt"
    Write-Host "Security events saved to C:\log.txt"
}
else {
    Write-Host "No security events found for user $username in the last week." -ForegroundColor Yellow
}
