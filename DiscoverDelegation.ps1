#Only include computer, can be modified to include users, service accounts etc
#only detect unconstrained delegation, there are constrained delegation, or resource-based-constrained-delegation that could be dangerous when exist in some objects, ie krbtgt
#https://adsecurity.org/?p=1667
param
(	
	[Parameter(ParameterSetName="Domain",Mandatory=$true)]
	[String] $Domain
		
					
)
Import-Module ActiveDirectory

Get-ADComputer -Server $Domain -Filter {(TrustedForDelegation -eq $True) -AND (PrimaryGroupID -eq 515) -OR (TrustedToAuthForDelegation -eq $True)} -Properties TrustedForDelegation,TrustedToAuthForDelegation,servicePrincipalName,Description | Export-Csv -Path .\DiscDelegation_com.csv -NoTypeInformation

Get-ADUser -Server $Domain -Filter {(TrustedForDelegation -eq $True) -OR (TrustedToAuthForDelegation -eq $True) -OR (msDS-AllowedToActOnBehalfOfOtherIdentity -like '*')} -Properties msds-AllowedToActOnBehalfOfOtherIdentity,TrustedForDelegation,TrustedToAuthForDelegation,servicePrincipalName,Description | Export-Csv -Path .\DiscDelegation_user.csv -NoTypeInformation 


