#
.NAME
    Exchange - Full Mailbox Access
.DESCRIPTION
    Exchange Full Mailbox Access
#>
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$CheckLockTool                   = New-Object system.Windows.Forms.Form
$CheckLockTool.ClientSize        = New-Object System.Drawing.Point(550,160)
$CheckLockTool.text              = "Exchange - Full Mailbox Access"
$CheckLockTool.TopMost           = $false

$AddAccess                     = New-Object system.Windows.Forms.Button
$AddAccess.text                = "Add Access"
$AddAccess.width               = 100
$AddAccess.height              = 30
$AddAccess.location            = New-Object System.Drawing.Point(200,39)
$AddAccess.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',8)
$AddAccess.ForeColor           = [System.Drawing.ColorTranslator]::FromHtml("#000000")
$AddAccess.BackColor           = [System.Drawing.ColorTranslator]::FromHtml("#fabc47")

$User                            = New-Object system.Windows.Forms.TextBox
$User.multiline                  = $false
$User.width                      = 174
$User.height                     = 25
$User.location                   = New-Object System.Drawing.Point(14,46)
$User.Font                       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Header                          = New-Object system.Windows.Forms.Label
$Header.text                     = "Enter User"
$Header.AutoSize                 = $true
$Header.width                    = 25
$Header.height                   = 10
$Header.location                 = New-Object System.Drawing.Point(12,26)
$Header.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$RemoveAccess                   = New-Object system.Windows.Forms.Button
$RemoveAccess.text              = "Remove Access"
$RemoveAccess.width             = 100
$RemoveAccess.height            = 30
$RemoveAccess.location          = New-Object System.Drawing.Point(310,39)
$RemoveAccess.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',8)
$RemoveAccess.BackColor         = [System.Drawing.ColorTranslator]::FromHtml("#81b772")


$CheckLockTool.controls.AddRange(@($AddAccess,$User,$Header,$RemoveAccess))

$AddAccess.Add_Click({ AddAccess })
$RemoveAccess.Add_Click({ RemoveAccess })

function AddAccess {

$Result = Get-ADUser -Identity $User.text -Properties Name, LastLogonDate, LockedOut, AccountLockOutTime, Enabled | select Name, LastLogonDate, LockedOut, AccountLockOutTime, Enabled 
$Result | Out-GridView -Title 'Locked Accounts'

    
}

function RemoveAccess { 
    Unlock-ADAccount -Identity $User.text
    
    $Result = Get-ADUser -Identity $User.text -Properties Name, LastLogonDate, LockedOut, AccountLockOutTime, Enabled | select Name, LastLogonDate, LockedOut, AccountLockOutTime, Enabled 
    $Result | Out-GridView -Title 'Unlocked Account'
}

#Write-Output
[void]$CheckLockTool.ShowDialog()