<#
.REQUIREMENTS
Run Powershell with elevated privileges
Requires LAPS to be installed locally.

.DESCRIPTION
Retrieve Local Administrator Password from LAPS

#>
Write-Host "Retrieve Local Administrator Password from LAPS"
Write-Host 
do{
$computername = Read-Host -Prompt "Enter Computer Name"
Get-AdmPwdPassword -ComputerName $computername
Write-Host
Write-Host
$respond = Read-Host "Repeat? Y"
}
While($respond -eq "Y")