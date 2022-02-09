$ComputerName = (get-wmiobject Win32_Computersystem).name
$ServiceName = $args[0]
$ServiceDisplayName = (Get-Service $ServiceName).DisplayName
$TimesRestarted = $args[1]
 
Get-Service $ServiceName
$Status = (Get-Service $ServiceName).Status
If ($Status -ne "Running")
{
Start-Service $ServiceName
}
 
function SendAlert
{
$FromAddress = "email@address.com"
$ToAddress = "email@address.com"
$MessageSubject = "Service Failure for $ComputerName"
$MessageBody = "The $ServiceDisplayName ($ServiceName) service on $ComputerName has restarted $TimesRestarted times in the last 24 hours, please investigate immediately"
$SendingServer = "EmailServerIPAddress"
 
###Create the mail message and add the statistics text file as an attachment
$SMTPMessage = New-Object System.Net.Mail.MailMessage $FromAddress, $ToAddress, $MessageSubject, $MessageBody
 
###Send the message
$SMTPClient = New-Object System.Net.Mail.SMTPClient $SendingServer
$SMTPClient.Send($SMTPMessage)
}
 
SendAlert