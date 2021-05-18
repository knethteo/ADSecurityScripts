$DomainName = Read-Host -Prompt 'Please enter the Domain Name'
.\ADPrivilegeAccounts-Audit-v3.ps1 -domain $DomainName
Write-Host "Review outputfile for more info"

.\DiscoverDelegation.ps1 -Domain $DomainName
If ((Get-Content ".\\DiscDelegation_com.csv") -ne $Null) {
Write-Host "Vulnerable to Delebation Abuse = Yes"
}
Else
{
Write-Host "Vulnerable to Delegation Abuse = No"
}

If ((Get-Content ".\\DiscDelegation_user.csv") -ne $Null) {
Write-Host "Vulnerable to user based Delebation Abuse = Yes"
}
Else
{
Write-Host "Vulnerable to user based Delegation Abuse = No"
}


.\PrivilegedAccountsRunningasKerberosServices.ps1 -Domain $DomainName
If ((Get-Content ".\PrivServ.csv") -ne $Null) {
Write-Host "Vulnerable to Kerberoastig Abuse = Yes"
}
Else
{
Write-Host "Vulnerable to Kerberoasting Abuse = No"
}

.\cpasswordGPOCredentialDiscovery.ps1 -Domain $DomainName
If ((Get-Content ".\GPOPWD.txt") -ne $Null) {
Write-Host "Vulnerable to GPP Password Abuse = Yes"
}
Else
{
Write-Host "Vulnerable to GPP Password Abuse = No"
}

.\AD-OU-ACE.ps1 -Domain $DomainName

Write-Host "check output files"
