#Get POTENTIALLY privileged users with SPN - high risk of kerberoasting
#POTENTIALLY because AdminCount is not a reliable way to check for privileged accounts

param
(	
	[Parameter(ParameterSetName="Domain",Mandatory=$true)]
	[String] $Domain
		
					
)

get-aduser -Server $Domain -filter {(AdminCount -eq 1) -AND (ServicePrincipalName -like "*") -AND (sAMAccountName -ne "krbtgt")} -Properties Name,AdminCount,ServicePrincipalName,PasswordLastSet,LastLogonDate,MemberOf | Export-Csv -Path .\PrivServ.csv -NoTypeInformation


get-aduser -Server $Domain -filter {(AdminCount -eq 1) -AND (ServicePrincipalName -like "*")} -Properties Name,AdminCount,ServicePrincipalName,PasswordLastSet,LastLogonDate,MemberOf > .\PrivServ.xml

get-adcomputer -Server $Domain -filter {(AdminCount -eq 1) -AND (ServicePrincipalName -like "*") -AND (sAMAccountName -ne "krbtgt")} -Properties Name,AdminCount,ServicePrincipalName,PasswordLastSet,LastLogonDate,MemberOf | Export-Csv -Path .\PrivServ.csv -NoTypeInformation -Append
get-adcomputer -Server $Domain -filter {(ServicePrincipalName -like "*")} -Properties Name,AdminCount,ServicePrincipalName,PasswordLastSet,LastLogonDate,MemberOf > .\PrivServComputer.xml