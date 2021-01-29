#Only include computer, can be modified to include users, service accounts etc
#only detect unconstrained delegation, there are constrained delegation, or resource-based-constrained-delegation that could be dangerous when exist in some objects, ie krbtgt
#https://adsecurity.org/?p=1667
Import-Module ActiveDirectory

Get-ADComputer -Filter {(TrustedForDelegation -eq $True) -AND (PrimaryGroupID -eq 515)} -Properties TrustedForDelegation,TrustedToAuthForDelegation,servicePrincipalName,Description | Export-Csv -Path .\WmiData.csv -NoTypeInformation
