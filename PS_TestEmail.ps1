<#
.DESCRIPTION
Test Exchange Email

.CREATED BY
Jason Thomas
Date: 2021-07-06

.NOTES
Requirement:  Your IP Address must be in the Relay List in Exchange

#>
do{
$from = Read-Host 'Enter FROM Email Address'
$to = Read-Host 'Enter TO Email Address'
$subject = Read-Host 'Enter SUBJECT'
$body = Read-Host 'Enter BODY'
$smtp = Read-Host 'Enter SMTP Server; Example: mail.domain.com'
Send-MailMessage -From $from -To $to -Subject $subject -Body $body -SmtpServer $smtp
$respond = Read-Host "Repeat? Y"
}
while($respond -eq "Y")