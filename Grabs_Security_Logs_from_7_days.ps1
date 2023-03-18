$today = Get-Date
$weekAgo = $today.AddDays(-7)
$username = $env:USERNAME
$logName = "Security"

$events = Get-WinEvent -FilterHashtable @{LogName=$logName;StartTime=$weekAgo;EndTime=$today;ID=4624,4634,4625,4728,4732,4756,1102,4740,4663;Level=0} -ErrorAction SilentlyContinue |
Where-Object {$_.Properties[5].Value -eq $username}

if ($events) {
    $events | Format-Table TimeCreated, Id, Message -AutoSize
}
else {
    Write-Host "No security events found for user $username in the last week." -ForegroundColor Yellow
}