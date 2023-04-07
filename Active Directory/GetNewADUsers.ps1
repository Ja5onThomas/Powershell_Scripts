# Import the Active Directory module
Import-Module ActiveDirectory

# Get the current date and time
$now = Get-Date

# Calculate the date and time 24 hours ago
$oneDayAgo = $now.AddDays(-1)

# Search for AD users created in the last day
$users = Get-ADUser -Filter {Created -ge $oneDayAgo} -Properties Created

# Output the results
$users | Select-Object Name, SamAccountName, Created