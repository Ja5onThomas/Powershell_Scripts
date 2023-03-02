Add-Type -AssemblyName System.Windows.Forms

$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Copy User Profile"
$Form.Size = New-Object System.Drawing.Size(400,200)

$Label1 = New-Object System.Windows.Forms.Label
$Label1.Location = New-Object System.Drawing.Point(10,20)
$Label1.Size = New-Object System.Drawing.Size(280,20)
$Label1.Text = "Enter the username of the user profile to copy:"
$Form.Controls.Add($Label1)

$TextBox1 = New-Object System.Windows.Forms.TextBox
$TextBox1.Location = New-Object System.Drawing.Point(10,40)
$TextBox1.Size = New-Object System.Drawing.Size(260,20)
$Form.Controls.Add($TextBox1)

$Label2 = New-Object System.Windows.Forms.Label
$Label2.Location = New-Object System.Drawing.Point(10,70)
$Label2.Size = New-Object System.Drawing.Size(280,20)
$Label2.Text = "Enter the name of the source computer:"
$Form.Controls.Add($Label2)

$TextBox2 = New-Object System.Windows.Forms.TextBox
$TextBox2.Location = New-Object System.Drawing.Point(10,90)
$TextBox2.Size = New-Object System.Drawing.Size(260,20)
$Form.Controls.Add($TextBox2)

$Label3 = New-Object System.Windows.Forms.Label
$Label3.Location = New-Object System.Drawing.Point(10,120)
$Label3.Size = New-Object System.Drawing.Size(280,20)
$Label3.Text = "Enter the name of the destination computer:"
$Form.Controls.Add($Label3)

$TextBox3 = New-Object System.Windows.Forms.TextBox
$TextBox3.Location = New-Object System.Drawing.Point(10,140)
$TextBox3.Size = New-Object System.Drawing.Size(260,20)
$Form.Controls.Add($TextBox3)

$Button1 = New-Object System.Windows.Forms.Button
$Button1.Location = New-Object System.Drawing.Point(280,40)
$Button1.Size = New-Object System.Drawing.Size(100,20)
$Button1.Text = "Copy Profile"
$Button1.Add_Click({
    $Username = $TextBox1.Text
    $SourceComputer = $TextBox2.Text
    $DestinationComputer = $TextBox3.Text
    $ProfilePath = "\\$SourceComputer\c$\Users\$Username"
    $DestinationPath = "\\$DestinationComputer\c$\Users\$Username"
    if(Test-Path $ProfilePath){
        Copy-Item $ProfilePath $DestinationPath -Recurse -Force
        [System.Windows.Forms.MessageBox]::Show("User profile has been copied to the destination computer.","Copy Complete",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)
    }
    else{
        [System.Windows.Forms.MessageBox]::Show("User profile not found on the source computer.","Error",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$Form.Controls.Add($Button1)

$Form.ShowDialog() | Out-Null
