$DCs = Get-ADDomainController -Filter *
$Results = New-Object -TypeName System.Collections.ArrayList
foreach($DC in $DCs){
    [string]$OMRoles = ""
    $ThisResult = New-Object -TypeName System.Object
    Add-Member -InputObject $ThisResult -MemberType NoteProperty -Name Name -Value $DC.Name
    Add-Member -InputObject $ThisResult -MemberType NoteProperty -Name Site -Value $DC.Site
    Add-Member -InputObject $ThisResult -MemberType NoteProperty -Name IPv4Address -Value $DC.IPv4Address
    Add-Member -InputObject $ThisResult -MemberType NoteProperty -Name OperatingSystemVersion -Value $DC.OperatingSystemVersion
    Add-Member -InputObject $ThisResult -MemberType NoteProperty -Name IsGlobalCatalog -Value $DC.IsGlobalCatalog
    Add-Member -InputObject $ThisResult -MemberType NoteProperty -Name IsReadOnly -Value $DC.IsReadOnly
    foreach($OMRole in $DC.OperationMasterRoles){
        $OMRoles += ([string]$OMRole+" ")
    }
    Add-Member -InputObject $ThisResult -MemberType NoteProperty -Name OperationMasterRoles -Value $OMRoles
    $Results.Add($ThisResult) | Out-Null
}
$Results = $Results | Sort-Object -Property Site
$Results | Format-Table -AutoSize 
$Results | Export-Csv c:\support\listdcs.csv