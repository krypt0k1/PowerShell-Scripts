# Check if the current user is an administrator

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") # If the current user is not an administrator, disable PowerShell script execution

if (!$isAdmin) {
    Write-Host "Disabling PowerShell script execution by non-admin users..."
    Set-ExecutionPolicy Restricted -Scope CurrentUser
    Write-Host "PowerShell script execution disabled for non-admin users."
} else {
    Write-Host "Current user is an administrator. No action taken."
}