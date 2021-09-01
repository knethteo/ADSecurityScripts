$title    = 'Disclaimer Confirmation'
$question = 'Have you read and understand the disclaimer and do you agree with the disclaimer? The disclaimer can be found here: https://bit.ly/tad_hcscript_disclaimer'

$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes, I have read, understand and agree the disclaimer'))
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No, I do not wish to proceed'))

$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -eq 0) {
    Write-Host 'confirmed'
} else {
    Write-Host 'cancelled'
}


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
