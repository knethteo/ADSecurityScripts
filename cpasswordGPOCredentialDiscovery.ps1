#Find potential password in cpassword read more here: https://adsecurity.org/?p=2288
#Negative result doesn't mean passwords do not exist in GPO files, it may be in other forms.
findstr /S /I /c:"cpassword" /c:"password" \\<FQDN>\sysvol\<FQDN>\policies\*.xml | Export-Csv -Path .\GPOPWD.csv -NoTypeInformation
