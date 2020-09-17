#Find potential password in cpassword read more here: https://adsecurity.org/?p=2288
#Negative result doesn't mean passwords do not exist in GPO files, it may be in other forms.
findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml
