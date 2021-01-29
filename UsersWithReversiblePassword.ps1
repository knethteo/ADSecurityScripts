Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl | Export-Csv -Path .\RevPwdUAC.csv -NoTypeInformation
