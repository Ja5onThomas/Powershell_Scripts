<#
************************************************************************************************************************
Created:	January 7, 2019
Version:	1.0
Disclaimer:
This script is provided "AS IS" with no warranties, confers no rights and 
is not supported by the author.
Author - Jason Thomas
************************************************************************************************************************
#>
# Check for elevation
Write-Host "Checking for elevation"

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "Oupps, you need to run this script from an elevated PowerShell prompt!`nPlease start the PowerShell prompt as an Administrator and re-run the script."
    Write-Warning "Aborting script..."
    Break
}

function mainMenu {
    $mainMenu = 'X'
    while($mainMenu -ne ''){
        Clear-Host
        Write-Host "`n`t`t Jason's Script`n"
        Write-Host -ForegroundColor Cyan "Main Menu"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Other Tools"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Active Directory Tools"
        $mainMenu = Read-Host "`nSelection (leave blank to quit)"
        # Launch submenu1
        if($mainMenu -eq 1){
            subMenu1
        }
        # Launch submenu2
        if($mainMenu -eq 2){
            subMenu2
        }
    }
}

function subMenu1 {
    $subMenu1 = 'X'
    while($subMenu1 -ne ''){
        Clear-Host
        Write-Host "`n`t`t My Script`n"
        Write-Host -ForegroundColor Cyan "Sub Menu 1"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Say hello"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Say goodbye"
        $subMenu1 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu1 -eq 1){
            Write-Host 'Hello!'
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu1 -eq 2){
            Write-Host 'Goodbye!'
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
    }
}

function subMenu2 {
    $subMenu2 = 'X'
    while($subMenu2 -ne ''){
        Clear-Host
        Write-Host "`n`t`t My Script`n"
        Write-Host -ForegroundColor Cyan "Sub Menu 2"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get Auto Services STOPPED"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Find Users Never Logged On"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Who is Logged in?"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Reboot Workstation or Server"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Ping Find Available IP Address"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Microsoft KB Articles 'ex: KB 968930'"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Resolve IP Address to Host Name Vice Versa"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Domain Admins in Active Directory"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "9"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Users in Active Directory"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "10"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Servers in Active Directory"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "11"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists Domain Controllers with FSMO roles"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "12"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Workstations in Active Directory"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "13"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Disabled User Accounts"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "14"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Locked User Accounts"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "15"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Organizational Units in Active Directory"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "16"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Users Password Expiry Date"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "17"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Unlock AD User Account"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "18"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Change AD User Password"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "19"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get the Computer Serial Number"
            Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "20"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Check Dell Warranty Status"
			Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "21"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get BIOS Information"
			Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "22"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List AD Account Password Never Expires"
			Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "23"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List HotFixes Installed"
			Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "24"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Check if HotFix has been Installed"
			Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "25"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get AD User List is a Member Of"
        $subMenu2 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu2 -eq 1){
            $ComputerName = Read-Host -Prompt 'Enter Computer Name'
            $Services_StartModeAuto = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "startmode='auto' AND state!='running'"| Select-Object DisplayName,Name,StartMode,State
            $Services_StartModeAuto | out-gridview
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu2 -eq 2){
            Get-ADUser -Filter { LastLogonDate -notlike "*" -and Enabled -eq $true } -Properties LastLogonDate | Select-Object @{ Name="Username"; Expression={$_.SamAccountName} }, Name, LastLogonDate, DistinguishedName | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 3
        if($subMenu2 -eq 3){
            $workstation = Read-Host -Prompt 'Enter Workstation Name'
            Get-WmiObject Win32_ComputerSystem -ComputerName $workstation | select username | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 4
        if($subMenu2 -eq 4){
            $workstation = Read-Host -Prompt 'Enter Workstation Name'
            Restart-Computer -ComputerName $workstation
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 5
        if($subMenu2 -eq 5){
            $network = Read-Host -Prompt 'Enter Subnet Ex: 191.1.1' 
            $iprange = 0..254
            Foreach ($ip in $iprange)
        {
            $computer = "$network.$ip"
            $status = Test-Connection $computer -count 1 -Quiet
        if (!$status)
        {
            $computer + " - available" 
        }
        
}
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 6
        if($subMenu2 -eq 6){
            $id = Read-Host -Prompt 'Enter KB Number'
            Start-Process "http://support.microsoft.com/kb/$id" 
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 7
        if($subMenu2 -eq 7){
            $ComputerName = Read-Host -Prompt 'Enter Computer Name'
            [Net.DNS]::GetHostEntry("$ComputerName") | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 8
        if($subMenu2 -eq 8){
            Get-ADGroupMember 'Domain Admins' | select Name, ObjectClass, SID | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 9
        if($subMenu2 -eq 9){
            Get-ADUser -Filter * | select Name, DistinguishedName, Enabled, SID | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 10
        if($subMenu2 -eq 10){
            Get-ADComputer -Filter "OperatingSystem -like '*Server*'" -properties OperatingSystem,OperatingSystemServicePack | Select Name,Op* | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 11
        if($subMenu2 -eq 11){
            Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, IsReadOnly, OperatingSystem, OperationMasterRoles | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 12
        if($subMenu2 -eq 12){
            Get-ADComputer -Filter "OperatingSystem -notLike '*Server*'" -properties OperatingSystem,OperatingSystemServicePack | Select Name,Op* | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 13
        if($subMenu2 -eq 13){
            Get-ADUser -filter {enabled -eq $false} | select  Name,DistinguishedName,SID,Enabled | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 14
        if($subMenu2 -eq 14){
            Search-ADAccount -LockedOut | Select Name,DistinguishedName,SID,Enabled,LockedOut | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 15
        if($subMenu2 -eq 15){
            Get-AdObject -Filter {ObjectClass -eq "OrganizationalUnit"} | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 16
        if($subMenu2 -eq 16){
            Get-ADUser -filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} -Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" | Select-Object -Property "Displayname",@{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}} | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 17
        if($subMenu2 -eq 17){
            $SAMName = Read-Host -Prompt 'Enter Username to Unlock'
            Unlock-ADAccount -Identity $SAMName
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 18
        if($subMenu2 -eq 18){
            $SAMName = Read-Host -Prompt 'Enter Username to Reset Password "Welcome1"'
            Set-ADAccountPassword –Identity $SAMName –Reset –NewPassword (ConvertTo-SecureString -AsPlainText "Welcome1" -Force)
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 19
        if($subMenu2 -eq 19){
            $computername = Read-Host -Prompt 'Enter the Workstation Name'
            get-wmiobject -ComputerName $computername -Class win32_bios | select PSComputerName,SerialNumber | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 20
        if($subMenu2 -eq 20){
            $sn = Read-Host -Prompt 'Enter Serial Number'
            Start-Process "https://www.dell.com/support/home/us/en/04/product-support/servicetag/$sn/warranty"
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 21
        if($subMenu2 -eq 21){
             $computername = Read-Host -Prompt 'Enter the Workstation Name'
 			 $os = Get-WmiObject Win32_bios -ComputerName $computername -ea silentlycontinue 
 			 if($os){ 
 
  			 $SerialNumber =$os.SerialNumber 
  			 $servername=$os.PSComputerName  
  			 $Name= $os.Name 
  			 $SMBIOSBIOSVersion=$os.SMBIOSBIOSVersion 
  			 $Manufacturer=$os.Manufacturer 
 
			 $results =new-object psobject 
 
			 $results |Add-Member noteproperty SerialNumber  $SerialNumber 
			 $results |Add-Member noteproperty ComputerName  $servername 
			 $results |Add-Member noteproperty Name  $Name 
 			 $results |Add-Member noteproperty SMBIOSBIOSVersion  $SMBIOSBIOSVersion 
			 $results |Add-Member noteproperty Manufacture   $Manufacture 
 
			 #Display the results 
 
			 $results | Select-Object computername,SMBIOSBIOSVersion,Name,Manufacture ,SerialNumber 
			 }
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 22
        if($subMenu2 -eq 22){
            Search-ADAccount -PasswordNeverExpires | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 23
        if($subMenu2 -eq 23){
            $computername = Read-Host -Prompt 'Enter the Workstation Name'
			Get-HotFix -ComputerName $computername | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 24
        if($subMenu2 -eq 24){
            $computername = Read-Host -Prompt 'Enter the Workstation Name'
			$hotfix = Read-Host -Prompt 'Enter HotFix Number'
			Get-HotFix -ComputerName $computername $hotfix | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 25
        if($subMenu2 -eq 25){
            $username = Read-Host -Prompt 'Enter Username'
			Get-ADPrincipalGroupMembership $username | select name | Out-GridView
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
    }
}

mainMenu