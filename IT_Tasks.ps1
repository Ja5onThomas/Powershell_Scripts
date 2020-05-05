<#
************************************************************************************************************************
Created:	January 7, 2019
Version:	1.0
Modified:   April 16, 2019
Disclaimer:
This script is provided "AS IS" with no warranties, confers no rights and 
is not supported by the author.
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
        Write-Host "`n`t`t ####  Script by Jason  ####`n"
        Write-Host -ForegroundColor Cyan "Main Menu"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Active Directory Tools"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Active Directory Audit Reports"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Administrator Tasks"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Exchange Tools"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Other Tools"
        $mainMenu = Read-Host "`nSelection (leave blank to quit)"
        # Launch submenu1
        if($mainMenu -eq 1){
            subMenu1
        }
        # Launch submenu2
        if($mainMenu -eq 2){
            subMenu2
        }
        # Launch submenu2
        if($mainMenu -eq 3){
            subMenu3
        }
        # Launch submenu2
        if($mainMenu -eq 4){
            subMenu4
        }
        # Launch submenu2
        if($mainMenu -eq 5){
            subMenu5
        }
    }
}

function subMenu1 {
    $subMenu1 = 'X'
    while($subMenu1 -ne ''){
        Clear-Host
        Write-Host "`n`t`t ####  Script by Jason  ####`n"
        Write-Host "`n`t`t    ACTIVE DIRECTORY TOOLS`n"
        Write-Host -ForegroundColor Cyan "Choose an option below"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Unlock Active Directory User Account"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Change Active Directory User Password"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Change Active Directory User Title"	
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Change Active Directory User Department"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Remove User from Active Directory Group"
        $subMenu1 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu1 -eq 1){
            $SAMName = Read-Host -Prompt 'Enter Username to Unlock'
            Unlock-ADAccount -Identity $SAMName
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu1 -eq 2){
            $SAMName = Read-Host -Prompt 'Enter Username to Reset Password "Welcome1"'
            Set-ADAccountPassword –Identity $SAMName –Reset –NewPassword (ConvertTo-SecureString -AsPlainText "Welcome1" -Force)
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 3
        if($subMenu1 -eq 3){
            $User = Read-Host -Prompt 'Enter Name'
			$Title  = Read-Host -Prompt 'Enter Title'
			Get-ADUser -Identity $User | Set-ADUser -Title $title
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 4
        if($subMenu1 -eq 4){
            $User = Read-Host -Prompt 'Enter Name'
			$Department  = Read-Host -Prompt 'Enter Department'
			Get-ADUser -Identity $User | Set-ADUser -Department $Department
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 5
        if($subMenu1 -eq 5){
            $username = Read-Host 'Enter Username to be removed'
			$adgroup = Read-Host 'Enter Active Directory Group Name'
			Remove-ADGroupMember -Identity $adgroup -Members $username
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
        Write-Host "`n`t`t ####  Script by Jason  ####`n"
        Write-Host "`n`t`t ACTIVE DIRECTORY AUDIT REPORTS`n"
        Write-Host -ForegroundColor Cyan "Choose an option below"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Find Users Never Logged On"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Domain Admins in Active Directory"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Users in Active Directory"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Servers in Active Directory"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists Domain Controllers with FSMO roles"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Workstations in Active Directory"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Disabled User Accounts"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Locked User Accounts"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "9"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Organizational Units in Active Directory"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "10"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lists all Users Password Expiry Date"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "11"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List Active Directory Account Password Never Expires"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "12"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get Active Directory User Member Of"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "13"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Audit Folder Permissions"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "14"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List All Users with Email Addresses"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "15"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List Users added in the last X Days"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "16"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List Computers added in the last X Days"	
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "17"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get a Count of All computers by Operating System"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "18"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get Domain Default Password Policy"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "19"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get all Fine Grained Password Policies"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "20"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get AD Users by Name"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "21"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List Inactive Computers"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "22"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List Deleted Active Directory Objects"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "23"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List Users in an Active Directory Group"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "24"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get All Active Directory Group and Users"
        $subMenu2 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu2 -eq 1){
            Get-ADUser -Filter { LastLogonDate -notlike "*" -and Enabled -eq $true } -Properties LastLogonDate | Select-Object @{ Name="Username"; Expression={$_.SamAccountName} }, Name, LastLogonDate, DistinguishedName | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu2 -eq 2){
           Get-ADGroupMember 'Domain Admins' | select Name, ObjectClass, SID | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 3 
        if($subMenu2 -eq 3){
           Get-ADUser -Filter * | select Name, DistinguishedName, Enabled, SID | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 4 
        if($subMenu2 -eq 4){
           Get-ADComputer -Filter "OperatingSystem -like '*Server*'" -properties OperatingSystem,OperatingSystemServicePack | Select Name,Op* | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 5 
        if($subMenu2 -eq 5){
           Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, IsReadOnly, OperatingSystem, OperationMasterRoles | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 6 
        if($subMenu2 -eq 6){
           Get-ADComputer -Filter "OperatingSystem -notLike '*Server*'" -properties OperatingSystem,OperatingSystemServicePack | Select Name,Op* | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 7 
        if($subMenu2 -eq 7){
           Get-ADUser -filter {enabled -eq $false} | select  Name,DistinguishedName,SID,Enabled | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 8 
        if($subMenu2 -eq 8){
           Search-ADAccount -LockedOut | Select Name,DistinguishedName,SID,Enabled,LockedOut | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 9 
        if($subMenu2 -eq 9){
           Get-AdObject -Filter {ObjectClass -eq "OrganizationalUnit"} | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 10 
        if($subMenu2 -eq 10){
           Get-ADUser -filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} -Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" | Select-Object -Property "Displayname",@{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}} | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 11 
        if($subMenu2 -eq 11){
           Search-ADAccount -PasswordNeverExpires | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 12 
        if($subMenu2 -eq 12){
           $username = Read-Host -Prompt 'Enter Username'
			Get-ADPrincipalGroupMembership $username | select name | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 13 
        if($subMenu2 -eq 13){
           $folderName = Read-Host -Prompt 'Enter Folder Name or Location'
			(get-acl $folderName).access | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 14 
        if($subMenu2 -eq 14){
           Get-ADUser -Filter * -Properties DisplayName, EmailAddress, Title, Telephonenumber, PhysicalDeliveryOfficeName, Description  | select DisplayName, EmailAddress, Title, Telephonenumber, PhysicalDeliveryOfficeName, Description | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 15 
        if($subMenu2 -eq 15){
           $Days = Read-Host -Prompt 'Enter Number of Days' 
			$checktime = (get-date).adddays(-$Days)
			get-aduser -searchbase "DC=FFFCU,DC=org" -Properties whencreated -filter {whencreated -ge $checktime} | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 16 
        if($subMenu2 -eq 16){
           $Days = Read-Host -Prompt 'Enter Number of Days' 
			$recently = [DateTime]::Today.AddDays(-$Days)
			Get-ADComputer -Filter 'WhenCreated -ge $recently' -Properties whenCreated | select Name,whenCreated,distinguishedName | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 17 
        if($subMenu2 -eq 17){
           Get-ADComputer -Filter "name -like '*'" -Properties operatingSystem | group -Property operatingSystem | Select Name,Count | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 18 
        if($subMenu2 -eq 18){
           Get-ADDefaultDomainPasswordPolicy | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 19 
        if($subMenu2 -eq 19){
           Get-ADFineGrainedPasswordPolicy -filter * | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 20 
        if($subMenu2 -eq 20){
           $name = Read-Host -Prompt 'Enter Name "ex *robert*"'
			get-Aduser -Filter {name -like $name} | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 21 
        if($subMenu2 -eq 21){
           $DaysInactive = Read-Host -Prompt 'Enter Inactive Days'
			$time = (Get-Date).Adddays(-($DaysInactive))
			Get-ADComputer -Filter {LastLogonTimeStamp -lt $time} -ResultPageSize 2000 -resultSetSize $null -Properties Name, OperatingSystem, SamAccountName, DistinguishedName | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 22 
        if($subMenu2 -eq 22){
           Get-ADObject -Filter 'isdeleted -eq $TRUE -and name -ne "Deleted Objects"' -IncludeDeletedObjects -Properties * | `
			Format-List samAccountName,displayName,lastknownParent,whenchanged 
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 23 
        if($subMenu2 -eq 23){
           $groups = @(Get-ADGroup -Filter * | Select-Object -ExpandProperty Name)
			$selectedGroup = $groups | Out-GridView -Title 'Select a group' -PassThru
			Get-ADGroupMember $selectedGroup -Recursive | Get-ADUser -Property DisplayName | Select Name,ObjectClass,DisplayName | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 24 
        if($subMenu2 -eq 24){
           $Groups = Get-ADGroup -Filter {GroupScope -eq 'Global' -and Members -ne "NULL"}
			$Users = foreach( $Group in $Groups ){
    			Get-ADGroupMember -Identity $Group | foreach {
       		 		[PSCustomObject]@{
            			Group = $Group.Name
            			UserName = $_.SamAccountName
        }
    }
}
			$Users | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
    }
}

function subMenu3 {
    $subMenu31 = 'X'
    while($subMenu3 -ne ''){
        Clear-Host
        Write-Host "`n`t`t ####  Script by Jason  ####`n"
        Write-Host "`n`t`t     ADMINISTRATOR TASKS`n"
        Write-Host -ForegroundColor Cyan "Choose an option below"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Who is Logged in?"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Reboot Workstation or Server"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Shutdown Workstation or Server"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get Error and Warning EventLog Entries by Date"		
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get System Uptime"	
        $subMenu3 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu3 -eq 1){
            $workstation = Read-Host -Prompt 'Enter Workstation Name'
            Get-WmiObject Win32_ComputerSystem -ComputerName $workstation | select username | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu3 -eq 2){
            $workstation = Read-Host -Prompt 'Enter Workstation Name'
            Restart-Computer -ComputerName $workstation -Force
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 3
        if($subMenu3 -eq 3){
            $workstation = Read-Host -Prompt 'Enter Workstation Name'
            Stop-Computer -ComputerName $workstation -Force
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 4
        if($subMenu3 -eq 4){
            $ComputerName = Read-Host -Prompt 'Enter Computer Name'
			$DateAfter = Read-Host -Prompt 'Enter Date After ex 05/08/2019'
			$DateBefore = Read-Host -Prompt 'Enter Date Before ex 05/08/2019'
			$LogType = Read-Host -Prompt 'Enter Log Type - "Application, Security, Setup, System"'
			Get-EventLog -ComputerName $ComputerName -LogName $LogType -After $DateAfter -Before $DateBefore | Where-Object {$_.EntryType -like 'Error' -or $_.EntryType -like 'Warning'} | Sort-Object Source
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 5
        if($subMenu3 -eq 5){
            $ComputerName = Read-Host -Prompt 'Enter Computer Name'
			systeminfo /S $ComputerName | find /i "Boot Time"
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
	}
}

function subMenu4 {
    $subMenu4 = 'X'
    while($subMenu4 -ne ''){
        Clear-Host
        Write-Host "`n`t`t ####  Script by Jason  ####`n"
        Write-Host "`n`t`t         EXCHANGE TOOLS`n"
        Write-Host -ForegroundColor Cyan "Choose an option below"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get Disabled Mailboxes by Database"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Permanently Delete User Mailbox"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List Disconnected Mailboxes"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List Active Sync Devices"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Add Full Mailbox Access"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Remove Full Mailbox Access"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Check Exchange Server Status"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Useful Information about Exchange"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "9"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Monitor Exchange Server Queue"

        $subMenu4 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu4 -eq 1){
            $Database = Read-Host -Prompt 'Enter Database Name'
            Get-MailboxStatistics -Database $Database | where {$_.DisconnectReason -eq "disabled"}
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu4 -eq 2){
            $username = Read-Host -Prompt 'Enter User Name'
            Remove-Mailbox -Identity $username -Permanent $true
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 3
        if($subMenu4 -eq 3){
            Get-MailboxDatabase | Get-MailboxStatistics | where { $_.DisconnectReason -ne $null } | Format-List DisplayName,MailboxGuid,Database,DisconnectReason
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 4
        if($subMenu4 -eq 4){
            Get-MobileDevice -ResultSize Unlimited | Select-Object @{Name='User';Expression={(Get-Mailbox -Identity $_.UserDisplayName) | Select-Object -expand WindowsEmailAddress}},DeviceID,DeviceImei,DeviceOS,DeviceType,DeviceUserAgent,DeviceModel | Out-Gridview
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 5
        if($subMenu4 -eq 5){
            $EmpName = Read-Host -Prompt 'Enter Employee Name'
			$YourName = Read-Host -Prompt 'Enter Requester Name'
			Add-MailboxPermission -Identity $EmpName -User $YourName -AccessRights FullAccess
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 6
        if($subMenu4 -eq 6){
            $EmpName = Read-Host -Prompt 'Enter Employee Name'
			$YourName = Read-Host -Prompt 'Enter Requester Name'
			Remove-MailboxPermission -Identity $EmpName -User $YourName -AccessRights FullAccess
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 7
        if($subMenu4 -eq 7){
            Get-Service -Name *Exchange* | select Status, DisplayName | sort Status | ft -AutoSize
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 8
        if($subMenu4 -eq 8){
            Get-ExchangeServer | select Fqdn, ServerRole, AdminDisplayVersion, IsEdgeServer | ft -AutoSize
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
		# Option 9
        if($subMenu4 -eq 9){
            Get-Queue -Identity Submission
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
    }
}

function subMenu5 {
    $subMenu5 = 'X'
    while($subMenu5 -ne ''){
        Clear-Host
        Write-Host "`n`t`t ####  Script by Jason  ####`n"
        Write-Host "`n`t`t         OTHER TOOLS`n"
        Write-Host -ForegroundColor Cyan "Choose an option below"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get Auto Services STOPPED"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Ping Find Available IP Address"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Microsoft KB Articles 'ex: KB 968930'"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Resolve IP Address to Host Name Vice Versa"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get the Computer Serial Number"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Check Dell Warranty Status"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get BIOS Information"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List HotFixes Installed"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "9"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Check if HotFix has been Installed"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "10"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " List Windows Services with Service Account"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "11"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " What Is My Public IP Address"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "12"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Copy Files & Folders"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "13"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Find and File and Check if it Exists"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "14"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " NSLOOKUP - IP Address / Hostname"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "15"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Trace Route - IP Address / Hostname"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "16"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Check for Open Port"	
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "17"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Shows current TCP/IP network connections"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "18"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Tips and Tricks"
		Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "19"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Get File Hash"
        $subMenu5 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu5 -eq 1){
            $ComputerName = Read-Host -Prompt 'Enter Computer Name'
            $Services_StartModeAuto = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "startmode='auto' AND state!='running'"| Select-Object DisplayName,Name,StartMode,State
            $Services_StartModeAuto | out-gridview
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu5 -eq 2){
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
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 3
        if($subMenu5 -eq 3){
            $id = Read-Host -Prompt 'Enter KB Number'
            Start-Process "http://support.microsoft.com/kb/$id" 
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
         # Option 4
        if($subMenu5 -eq 4){
            $ComputerName = Read-Host -Prompt 'Enter Computer Name'
            [Net.DNS]::GetHostEntry("$ComputerName") | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
         # Option 5
        if($subMenu5 -eq 5){
            $computername = Read-Host -Prompt 'Enter the Workstation Name'
            get-wmiobject -ComputerName $computername -Class win32_bios | select PSComputerName,SerialNumber | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
         # Option 6
        if($subMenu5 -eq 6){
            $sn = Read-Host -Prompt 'Enter Serial Number'
            Start-Process "https://www.dell.com/support/home/us/en/04/product-support/servicetag/$sn/warranty"
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
         # Option 7
        if($subMenu5 -eq 7){
            $computername = Read-Host -Prompt 'Enter the Workstation Name'
 			 $os = Get-WmiObject Win32_bios -ComputerName $computername -ea silentlycontinue 
 			 if($os) {
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
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
         # Option 8
        if($subMenu5 -eq 8){
            $computername = Read-Host -Prompt 'Enter the Workstation Name'
			Get-HotFix -ComputerName $computername | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
         # Option 9
        if($subMenu5 -eq 9){
            $computername = Read-Host -Prompt 'Enter the Workstation Name'
			$hotfix = Read-Host -Prompt 'Enter HotFix Number'
			Get-HotFix -ComputerName $computername $hotfix | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
         # Option 10
        if($subMenu5 -eq 10){
            $servers = get-adcomputer -filter {operatingsystem -like "*server*"};
 
            foreach ($server in $servers) {
            $services = $null;
            $services = gwmi win32_service -computer $server.name -ErrorAction SilentlyContinue | where {($_.startname -like "*FFCU*")};
 
            if ($services -ne $null) {
            foreach ($service in $services) {
            write-host $server.name - $service.caption - $service.startname;
			
         }
    }
}
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
		 # Option 11
        if($subMenu5 -eq 11){
            Invoke-RestMethod -Uri https://checkip.amazonaws.com
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
		 # Option 12
        if($subMenu5 -eq 12){
            $SourceFile = Read-Host -Prompt 'Enter Source Location'
			$DestinationFile = Read-Host -Prompt 'Enter Destination Location'
			copy-item  "$SourceFile" -destination "$DestinationFile" -recurse -verbose
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
		 # Option 13
        if($subMenu5 -eq 13){
            $filename = Read-Host -Prompt 'Enter File Name. Example: *file*.* wildcards for extension'
			$searchinfolder = Read-Host -Prompt 'Enter Folder to Search. include *'
			Get-ChildItem -Path $searchinfolder -Filter $filename -Recurse | %{$_.FullName}
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
		 # Option 14
        if($subMenu5 -eq 14){
            $IPAddress = Read-Host -Prompt 'Enter IP Address or domain name'
			nslookup $IPAddress
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
		 # Option 15
        if($subMenu5 -eq 15){
            $IPAddress = Read-Host -Prompt 'Enter IP Address or Hostname'
			Test-NetConnection $IPAddress -TraceRoute
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
		 # Option 16
        if($subMenu5 -eq 16){
            $ComputerName = Read-Host -Prompt 'Enter IP Address or Hostname'
			$Port = Read-Host -Prompt 'Enter Port Number'
			Test-NetConnection -ComputerName $ComputerName -Port $Port
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
		  # Option 17
        if($subMenu5 -eq 17){
            Get-NetTCPConnection | ? State -eq Established | Out-GridView
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
		 # Option 18
        if($subMenu5 -eq 18){
            write-host ""
			write-host "Tip #1" -foreground Green
			write-host "Tip #2"
			write-host "Tip #3"
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
		 # Option 19
        if($subMenu5 -eq 19){
            $Hash = Read-Host "Enter File Path and Name"
			Get-FileHash $Hash
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
         }
    }
}

mainMenu
