#Get POTENTIALLY privileged users with SPN - high risk of kerberoasting
#POTENTIALLY because AdminCount is not a reliable way to check for privileged accounts
get-aduser -filter {(AdminCount -eq 1) -AND (ServicePrincipalName -notlike "*")} -Properties Name,AdminCount,ServicePrincipalName,PasswordLastSet,LastLogonDate,MemberOf | Export-Csv -Path .\WmiData.csv -NoTypeInformation
